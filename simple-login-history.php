<?php
/**
 * Plugin Name: Simple Login History
 * Description: Tracks WordPress login attempts, active sessions, logout times, browser, OS, IP address, and user agent in a local admin report.
 * Version: 1.2.8
 * Author: Jason Cox
 * Plugin URI: https://github.com/jcjason12108-alt/simple-login-history
 * Requires at least: 5.8
 * Tested up to: 7.0
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 * Text Domain: simple-login-history
 */

if (!defined('ABSPATH')) {
	exit;
}

if (file_exists(__DIR__ . '/plugin-update-checker/plugin-update-checker.php')) {
	require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';

	$slh_update_checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
		'https://github.com/jcjason12108-alt/simple-login-history/',
		__FILE__,
		'simple-login-history'
	);
	$slh_update_checker->setBranch('main');
	add_filter(
		$slh_update_checker->getUniqueName('vcs_update_detection_strategies'),
		static function (array $strategies): array {
			return isset($strategies['branch']) ? ['branch' => $strategies['branch']] : $strategies;
		}
	);

	$slh_github_token = defined('SLH_UPDATE_GITHUB_TOKEN') ? SLH_UPDATE_GITHUB_TOKEN : getenv('SLH_UPDATE_GITHUB_TOKEN');
	if (!empty($slh_github_token)) {
		$slh_update_checker->setAuthentication($slh_github_token);
	}
}

final class Simple_Login_History {
	private const VERSION = '1.2.8';
	private const TABLE_SUFFIX = 'simple_login_history';
	private const SESSION_COOKIE = 'slh_session';
	private const LAST_SEEN_META = '_slh_last_seen_update';
	private const ACTIVITY_META = '_slh_last_activity';
	private const OPTION_NAME = 'simple_login_history_options';
	private const LL706_IMPORT_OPTION = 'simple_login_history_ll706_imported_version';
	private const CLEANUP_HOOK = 'simple_login_history_cleanup';

	private static ?self $instance = null;

	public static function instance(): self {
		if (null === self::$instance) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	private function __construct() {
		add_action('wp_login', [$this, 'record_successful_login'], 10, 2);
		add_action('wp_login_failed', [$this, 'record_failed_login']);
		add_action('wp_logout', [$this, 'record_logout']);
		add_action('plugins_loaded', [$this, 'maybe_upgrade_database']);
		add_action('plugins_loaded', [$this, 'maybe_import_ll706_app_logins_once'], 20);
		add_action('init', [$this, 'maybe_schedule_cleanup']);
		add_action('init', [$this, 'maybe_auto_logout']);
		add_action('init', [$this, 'record_last_seen']);
		add_action('admin_menu', [$this, 'register_admin_page']);
		add_action('admin_post_slh_save_settings', [$this, 'save_settings']);
		add_action('admin_post_slh_export', [$this, 'export_csv']);
		add_action(self::CLEANUP_HOOK, [$this, 'cleanup_old_records']);
		add_filter('rest_request_after_callbacks', [$this, 'record_app_login_from_rest_response'], 10, 3);
		add_filter('set_screen_option_slh_login_history_per_page', [$this, 'save_screen_option'], 10, 3);
	}

	public static function activate(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table = self::table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NULL,
			username varchar(191) NOT NULL DEFAULT '',
			role varchar(191) NOT NULL DEFAULT '',
			old_role varchar(191) NOT NULL DEFAULT '',
			ip_address varchar(100) NOT NULL DEFAULT '',
			browser varchar(191) NOT NULL DEFAULT '',
			operating_system varchar(191) NOT NULL DEFAULT '',
			timezone varchar(100) NOT NULL DEFAULT '',
			country varchar(100) NOT NULL DEFAULT '',
			user_agent text NULL,
			login_at datetime NOT NULL,
			logout_at datetime NULL,
			last_seen_at datetime NULL,
			status varchar(20) NOT NULL DEFAULT 'logged_in',
			source varchar(20) NOT NULL DEFAULT 'wordpress',
			session_token varchar(64) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY user_id (user_id),
			KEY username (username),
			KEY login_at (login_at),
			KEY status (status),
			KEY source (source),
			KEY session_token (session_token)
		) {$charset_collate};";

		dbDelta($sql);
		add_option(self::OPTION_NAME, self::default_options());
		update_option('simple_login_history_version', self::VERSION);

		if (!wp_next_scheduled(self::CLEANUP_HOOK)) {
			wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CLEANUP_HOOK);
		}
	}

	public static function uninstall(): void {
		global $wpdb;

		$table = self::table_name();
		$wpdb->query("DROP TABLE IF EXISTS {$table}");
		delete_option(self::OPTION_NAME);
		delete_option(self::LL706_IMPORT_OPTION);
		delete_option('simple_login_history_version');
		wp_clear_scheduled_hook(self::CLEANUP_HOOK);
	}

	public static function table_name(): string {
		global $wpdb;

		return $wpdb->prefix . self::TABLE_SUFFIX;
	}

	public function maybe_upgrade_database(): void {
		if (get_option('simple_login_history_version') !== self::VERSION) {
			self::activate();
			$this->refresh_app_login_statuses();
		}
	}

	public function maybe_import_ll706_app_logins_once(): void {
		if (get_option(self::LL706_IMPORT_OPTION) === self::VERSION) {
			return;
		}

		if (!$this->options()['track_app_logins']) {
			return;
		}

		$this->import_ll706_app_logins();
		update_option(self::LL706_IMPORT_OPTION, self::VERSION, false);
	}

	private static function default_options(): array {
		return [
			'store_ip' => 1,
			'track_wordpress_logins' => 1,
			'track_app_logins' => 1,
			'track_roles' => [],
			'auto_logout_minutes' => 0,
			'auto_logout_roles' => [],
			'auto_delete_days' => 0,
			'email_success' => 0,
			'email_failed' => 0,
			'email_roles' => [],
			'email_to' => get_option('admin_email'),
			'csv_separator' => ',',
		];
	}

	private function options(): array {
		$options = get_option(self::OPTION_NAME, []);
		if (!is_array($options)) {
			$options = [];
		}

		return array_merge(self::default_options(), $options);
	}

	public function record_successful_login(string $user_login, WP_User $user): void {
		global $wpdb;

		if (!$this->options()['track_wordpress_logins']) {
			return;
		}

		if (!$this->should_track_user($user, 'track_roles')) {
			return;
		}

		$session_token = wp_generate_password(32, false, false);
		$roles = $this->get_user_roles($user);
		$user_agent = $this->get_user_agent();
		$options = $this->options();

		$wpdb->insert(
			self::table_name(),
			[
				'user_id' => (int) $user->ID,
				'username' => $user_login,
				'role' => $roles,
				'old_role' => $roles,
				'ip_address' => $options['store_ip'] ? $this->get_ip_address() : '',
				'browser' => $this->detect_browser($user_agent),
				'operating_system' => $this->detect_operating_system($user_agent),
				'timezone' => $this->get_site_timezone(),
				'country' => '',
				'user_agent' => $user_agent,
				'login_at' => current_time('mysql'),
				'last_seen_at' => current_time('mysql'),
				'status' => 'logged_in',
				'source' => 'wordpress',
				'session_token' => $session_token,
			],
			['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
		);

		$this->set_session_cookie($session_token);
		update_user_meta((int) $user->ID, self::ACTIVITY_META, time());
		$this->maybe_send_email_alert('success', $user, $user_login);
	}

	public function record_failed_login(string $username): void {
		global $wpdb;

		if (!$this->options()['track_wordpress_logins']) {
			return;
		}

		if ($this->is_ll706_app_login_request()) {
			return;
		}

		$user_agent = $this->get_user_agent();
		$options = $this->options();

		$wpdb->insert(
			self::table_name(),
			[
				'user_id' => null,
				'username' => sanitize_user($username),
				'role' => '',
				'old_role' => '',
				'ip_address' => $options['store_ip'] ? $this->get_ip_address() : '',
				'browser' => $this->detect_browser($user_agent),
				'operating_system' => $this->detect_operating_system($user_agent),
				'timezone' => $this->get_site_timezone(),
				'country' => '',
				'user_agent' => $user_agent,
				'login_at' => current_time('mysql'),
				'last_seen_at' => null,
				'status' => 'failed',
				'source' => 'wordpress',
				'session_token' => '',
			],
			['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
		);

		$this->maybe_send_email_alert('failed', null, sanitize_user($username));
	}

	public function record_app_login_from_rest_response($response, array $handler, WP_REST_Request $request) {
		if ('/ll706/v1/login' !== $request->get_route()) {
			return $response;
		}

		if (!$this->options()['track_app_logins']) {
			return $response;
		}

		$status_code = $this->rest_response_status($response);
		if ($status_code >= 200 && $status_code < 300) {
			$this->record_successful_app_login($response);
			return $response;
		}

		$this->record_failed_app_login($request);

		return $response;
	}

	private function record_successful_app_login($response): void {
		$data = $this->rest_response_data($response);
		$user_data = is_array($data['user'] ?? null) ? $data['user'] : [];
		$user_id = absint($user_data['user_id'] ?? 0);
		$user = $user_id ? get_user_by('id', $user_id) : false;

		if (!$user instanceof WP_User) {
			return;
		}

		if (!$this->should_track_user($user, 'track_roles')) {
			return;
		}

		$expires_at = isset($data['expires_at']) ? (int) $data['expires_at'] : 0;
		$app_status = $expires_at && $expires_at <= time() ? 'expired' : 'active';

		$this->insert_login_record([
			'user_id' => (int) $user->ID,
			'username' => $user->user_login,
			'role' => $this->get_user_roles($user),
			'old_role' => $this->get_user_roles($user),
			'status' => $app_status,
			'source' => 'app',
			'last_seen_at' => current_time('mysql'),
			'session_token' => '',
		]);

		$this->maybe_send_email_alert('success', $user, $user->user_login);
	}

	private function record_failed_app_login(WP_REST_Request $request): void {
		$username = sanitize_user((string) wp_unslash($request->get_param('username')));

		$this->insert_login_record([
			'user_id' => null,
			'username' => $username,
			'role' => '',
			'old_role' => '',
			'status' => 'failed',
			'source' => 'app',
			'last_seen_at' => null,
			'session_token' => '',
		]);

		$this->maybe_send_email_alert('failed', null, $username);
	}

	private function insert_login_record(array $overrides): void {
		global $wpdb;

		$user_agent = $this->get_user_agent();
		$options = $this->options();
		$data = array_merge(
			[
				'user_id' => null,
				'username' => '',
				'role' => '',
				'old_role' => '',
				'ip_address' => $options['store_ip'] ? $this->get_ip_address() : '',
				'browser' => $this->detect_browser($user_agent),
				'operating_system' => $this->detect_operating_system($user_agent),
				'timezone' => $this->get_site_timezone(),
				'country' => '',
				'user_agent' => $user_agent,
				'login_at' => current_time('mysql'),
				'last_seen_at' => null,
				'status' => 'logged_in',
				'source' => 'wordpress',
				'session_token' => '',
			],
			$overrides
		);

		$wpdb->insert(
			self::table_name(),
			$data,
			['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s']
		);
	}

	private function import_ll706_app_logins(): void {
		global $wpdb;

		if (!$this->options()['track_app_logins']) {
			return;
		}

		$source_table = $wpdb->prefix . 'll706_auth_login_log';
		$table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $source_table));
		if ($table_exists !== $source_table) {
			return;
		}

		$rows = $wpdb->get_results("SELECT user_id, username, role, ip_address, user_agent, logged_in_at, expires_at, token_version FROM {$source_table} ORDER BY logged_in_at DESC LIMIT 5000");
		if (!$rows) {
			return;
		}

		foreach ($rows as $row) {
			$login_at = get_date_from_gmt((string) $row->logged_in_at, 'Y-m-d H:i:s');
			$already_imported = (int) $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM ' . self::table_name() . ' WHERE source = %s AND user_id = %d AND login_at = %s',
					'app',
					(int) $row->user_id,
					$login_at
				)
			);

			if ($already_imported) {
				continue;
			}

			$user = get_user_by('id', (int) $row->user_id);
			$role = $user instanceof WP_User ? $this->get_user_roles($user) : (string) $row->role;
			$user_agent = (string) $row->user_agent;
			$app_status = $this->app_status_from_auth_row($row->expires_at ?? null, $row->token_version ?? null);

			$this->insert_login_record([
				'user_id' => (int) $row->user_id,
				'username' => (string) $row->username,
				'role' => $role,
				'old_role' => $role,
				'ip_address' => $this->options()['store_ip'] ? (string) $row->ip_address : '',
				'browser' => $this->detect_browser($user_agent),
				'operating_system' => $this->detect_operating_system($user_agent),
				'user_agent' => $user_agent,
				'login_at' => $login_at,
				'last_seen_at' => $login_at,
				'status' => $app_status,
				'source' => 'app',
				'session_token' => '',
			]);
		}
	}

	private function refresh_app_login_statuses(): void {
		global $wpdb;

		$source_table = $wpdb->prefix . 'll706_auth_login_log';
		$table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $source_table));
		if ($table_exists !== $source_table) {
			return;
		}

		$rows = $wpdb->get_results("SELECT user_id, logged_in_at, expires_at, token_version FROM {$source_table} ORDER BY logged_in_at DESC LIMIT 5000");
		if (!$rows) {
			return;
		}

		foreach ($rows as $row) {
			$login_at = get_date_from_gmt((string) $row->logged_in_at, 'Y-m-d H:i:s');
			$wpdb->update(
				self::table_name(),
				['status' => $this->app_status_from_auth_row($row->expires_at ?? null, $row->token_version ?? null)],
				[
					'source' => 'app',
					'user_id' => (int) $row->user_id,
					'login_at' => $login_at,
				],
				['%s'],
				['%s', '%d', '%s']
			);
		}
	}

	private function app_status_from_auth_row($expires_at, $token_version): string {
		$options = get_option('ll706_auth_api_options', []);
		$current_token_version = is_array($options) ? (int) ($options['token_version'] ?? 1) : 1;

		if ((int) $token_version !== $current_token_version) {
			return 'invalidated';
		}

		if (!$expires_at) {
			return 'expired';
		}

		$expires_timestamp = strtotime((string) $expires_at . ' UTC');

		return $expires_timestamp && $expires_timestamp > time() ? 'active' : 'expired';
	}

	private function rest_response_status($response): int {
		if ($response instanceof WP_REST_Response) {
			return (int) $response->get_status();
		}

		if ($response instanceof WP_Error) {
			$data = $response->get_error_data();
			return is_array($data) && isset($data['status']) ? (int) $data['status'] : 500;
		}

		return 200;
	}

	private function rest_response_data($response): array {
		if ($response instanceof WP_REST_Response) {
			$data = $response->get_data();
			return is_array($data) ? $data : [];
		}

		return [];
	}

	private function is_ll706_app_login_request(): bool {
		if (!defined('REST_REQUEST') || !REST_REQUEST || empty($_SERVER['REQUEST_URI'])) {
			return false;
		}

		$path = (string) wp_parse_url((string) wp_unslash($_SERVER['REQUEST_URI']), PHP_URL_PATH);

		return (bool) preg_match('#/wp-json/ll706/v1/login/?$#', $path);
	}

	public function record_logout(): void {
		global $wpdb;

		$session_token = $this->get_session_cookie();
		if ('' === $session_token) {
			return;
		}

		$wpdb->update(
			self::table_name(),
			[
				'logout_at' => current_time('mysql'),
				'last_seen_at' => current_time('mysql'),
				'status' => 'logged_out',
			],
			[
				'session_token' => $session_token,
				'status' => 'logged_in',
			],
			['%s', '%s', '%s'],
			['%s', '%s']
		);

		$this->clear_session_cookie();
	}

	public function maybe_auto_logout(): void {
		if (!is_user_logged_in()) {
			return;
		}

		$user = wp_get_current_user();
		if (!$user instanceof WP_User || !$this->should_track_user($user, 'auto_logout_roles')) {
			update_user_meta(get_current_user_id(), self::ACTIVITY_META, time());
			return;
		}

		$options = $this->options();
		$minutes = absint($options['auto_logout_minutes']);
		if (!$minutes) {
			update_user_meta(get_current_user_id(), self::ACTIVITY_META, time());
			return;
		}

		$last_activity = (int) get_user_meta(get_current_user_id(), self::ACTIVITY_META, true);
		if (!$last_activity) {
			update_user_meta(get_current_user_id(), self::ACTIVITY_META, time());
			return;
		}

		if ($last_activity > time() - ($minutes * MINUTE_IN_SECONDS)) {
			update_user_meta(get_current_user_id(), self::ACTIVITY_META, time());
			return;
		}

		$this->record_logout();
		wp_logout();
		wp_safe_redirect(wp_login_url());
		exit;
	}

	public function record_last_seen(): void {
		if (!is_user_logged_in()) {
			return;
		}

		$user_id = get_current_user_id();
		$last_update = (int) get_user_meta($user_id, self::LAST_SEEN_META, true);

		if ($last_update > time() - 60) {
			return;
		}

		global $wpdb;

		$session_token = $this->get_session_cookie();
		if ('' === $session_token) {
			return;
		}

		$wpdb->update(
			self::table_name(),
			['last_seen_at' => current_time('mysql')],
			[
				'session_token' => $session_token,
				'status' => 'logged_in',
			],
			['%s'],
			['%s', '%s']
		);

		update_user_meta($user_id, self::LAST_SEEN_META, time());
	}

	public function cleanup_old_records(): void {
		global $wpdb;

		$days = absint($this->options()['auto_delete_days']);
		if (!$days) {
			return;
		}

		$table = self::table_name();
		$cutoff = gmdate('Y-m-d H:i:s', current_time('timestamp') - ($days * DAY_IN_SECONDS));
		$wpdb->query($wpdb->prepare("DELETE FROM {$table} WHERE login_at < %s", $cutoff));
	}

	public function maybe_schedule_cleanup(): void {
		if (!wp_next_scheduled(self::CLEANUP_HOOK)) {
			wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', self::CLEANUP_HOOK);
		}
	}

	public function register_admin_page(): void {
		$hook = add_menu_page(
			__('Login History', 'simple-login-history'),
			__('Login History', 'simple-login-history'),
			'manage_options',
			'simple-login-history',
			[$this, 'render_admin_page'],
			'dashicons-clock',
			58
		);

		add_action("load-{$hook}", [$this, 'add_screen_options']);

		add_submenu_page(
			'simple-login-history',
			__('Login List', 'simple-login-history'),
			__('Login List', 'simple-login-history'),
			'manage_options',
			'simple-login-history',
			[$this, 'render_admin_page']
		);

		add_submenu_page(
			'simple-login-history',
			__('Login History Settings', 'simple-login-history'),
			__('Settings', 'simple-login-history'),
			'manage_options',
			'simple-login-history-settings',
			[$this, 'render_settings_page']
		);
	}

	public function add_screen_options(): void {
		add_screen_option(
			'per_page',
			[
				'label' => __('Login history entries', 'simple-login-history'),
				'default' => 20,
				'option' => 'slh_login_history_per_page',
			]
		);
	}

	public function save_screen_option($status, string $option, int $value) {
		if ('slh_login_history_per_page' === $option) {
			return max(1, min(200, $value));
		}

		return $status;
	}

	public function render_admin_page(): void {
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('You do not have permission to view login history.', 'simple-login-history'));
		}

		$this->handle_admin_actions();
		$this->refresh_app_login_statuses();

		$page = max(1, absint($_GET['paged'] ?? 1));
		$per_page = (int) get_user_option('slh_login_history_per_page');
		$per_page = $per_page > 0 ? $per_page : 20;
		$search = sanitize_text_field(wp_unslash($_GET['s'] ?? ''));
		$status = sanitize_key($_GET['status'] ?? '');
		$source = $this->sanitize_source($_GET['source'] ?? '');
		$order_by = $this->sanitize_order_by($_GET['orderby'] ?? 'login_at');
		$order = ('asc' === strtolower((string) ($_GET['order'] ?? 'desc'))) ? 'ASC' : 'DESC';

		$records = $this->get_records($page, $per_page, $search, $status, $source, $order_by, $order);
		$total = $this->count_records($search, $status, $source);
		$total_pages = max(1, (int) ceil($total / $per_page));

		?>
		<div class="wrap">
			<h1><?php esc_html_e('Login History', 'simple-login-history'); ?></h1>
			<p>
				<a class="button" href="<?php echo esc_url(admin_url('admin.php?page=simple-login-history-settings')); ?>"><?php esc_html_e('Settings', 'simple-login-history'); ?></a>
				<a class="button" href="<?php echo esc_url($this->export_url($search, $status, $source, $order_by, $order)); ?>"><?php esc_html_e('Export CSV', 'simple-login-history'); ?></a>
			</p>
			<form method="get">
				<input type="hidden" name="page" value="simple-login-history" />
				<input type="hidden" name="status" value="<?php echo esc_attr($status); ?>" />
				<input type="hidden" name="source" value="<?php echo esc_attr($source); ?>" />
				<p class="search-box">
					<label class="screen-reader-text" for="slh-search-input"><?php esc_html_e('Search Login History', 'simple-login-history'); ?></label>
					<input type="search" id="slh-search-input" name="s" value="<?php echo esc_attr($search); ?>" />
					<?php submit_button(__('Search', 'simple-login-history'), '', '', false); ?>
				</p>
			</form>
			<form method="post">
				<?php wp_nonce_field('slh_bulk_action', 'slh_nonce'); ?>
				<div class="tablenav top">
					<div class="alignleft actions bulkactions">
						<label for="slh-bulk-action-selector" class="screen-reader-text"><?php esc_html_e('Select bulk action', 'simple-login-history'); ?></label>
						<select name="action" id="slh-bulk-action-selector">
							<option value="-1"><?php esc_html_e('Bulk actions', 'simple-login-history'); ?></option>
							<option value="delete"><?php esc_html_e('Delete', 'simple-login-history'); ?></option>
						</select>
						<?php submit_button(__('Apply', 'simple-login-history'), 'action', '', false); ?>
					</div>
					<div class="alignleft actions">
						<label for="slh-status-filter" class="screen-reader-text"><?php esc_html_e('Filter by status', 'simple-login-history'); ?></label>
						<select name="status" id="slh-status-filter" onchange="window.location.href=this.value;">
							<?php echo $this->status_filter_options($status, $source); ?>
						</select>
					</div>
					<div class="alignleft actions">
						<label for="slh-source-filter" class="screen-reader-text"><?php esc_html_e('Filter by source', 'simple-login-history'); ?></label>
						<select name="source" id="slh-source-filter" onchange="window.location.href=this.value;">
							<?php echo $this->source_filter_options($source, $status); ?>
						</select>
					</div>
					<?php $this->pagination($page, $total_pages, $total, $search, $status, $source, $order_by, $order); ?>
				</div>
				<div class="slh-table-wrap">
					<table class="wp-list-table widefat striped table-view-list slh-login-table">
						<thead>
							<tr>
								<td class="manage-column column-cb check-column"><input type="checkbox" /></td>
								<?php $this->header_cell('source', __('Source', 'simple-login-history'), $order_by, $order); ?>
								<?php $this->header_cell('user_id', __('User ID', 'simple-login-history'), $order_by, $order); ?>
								<?php $this->header_cell('username', __('Username', 'simple-login-history'), $order_by, $order); ?>
								<th><?php esc_html_e('Role', 'simple-login-history'); ?></th>
								<th><?php esc_html_e('Old Role', 'simple-login-history'); ?></th>
								<th><?php esc_html_e('Browser', 'simple-login-history'); ?></th>
								<th><?php esc_html_e('Operating System', 'simple-login-history'); ?></th>
								<?php $this->header_cell('ip_address', __('IP Address', 'simple-login-history'), $order_by, $order); ?>
								<th><?php esc_html_e('Timezone', 'simple-login-history'); ?></th>
								<th><?php esc_html_e('Country', 'simple-login-history'); ?></th>
								<th><?php esc_html_e('User Agent', 'simple-login-history'); ?></th>
								<th><?php esc_html_e('Duration', 'simple-login-history'); ?></th>
								<th><?php esc_html_e('Last Seen', 'simple-login-history'); ?></th>
								<?php $this->header_cell('login_at', __('Login', 'simple-login-history'), $order_by, $order); ?>
								<?php $this->header_cell('logout_at', __('Logout', 'simple-login-history'), $order_by, $order); ?>
								<?php $this->header_cell('status', __('Login Status', 'simple-login-history'), $order_by, $order); ?>
							</tr>
						</thead>
						<tbody>
							<?php if ($records) : ?>
								<?php foreach ($records as $record) : ?>
									<tr>
										<th scope="row" class="check-column"><input type="checkbox" name="record_ids[]" value="<?php echo esc_attr((int) $record->id); ?>" /></th>
										<td><?php echo esc_html($this->format_source($record->source ?? 'wordpress')); ?></td>
										<td><?php echo $record->user_id ? esc_html((string) $record->user_id) : '&mdash;'; ?></td>
										<td>
											<?php if ($record->user_id) : ?>
												<a href="<?php echo esc_url(get_edit_user_link((int) $record->user_id)); ?>"><?php echo esc_html($record->username); ?></a>
											<?php else : ?>
												<?php echo esc_html($record->username); ?>
											<?php endif; ?>
											<div class="row-actions">
												<span class="delete">
													<a href="<?php echo esc_url($this->delete_url((int) $record->id)); ?>" class="submitdelete"><?php esc_html_e('Delete', 'simple-login-history'); ?></a>
												</span>
											</div>
										</td>
										<td><?php echo esc_html($record->role ?: '-'); ?></td>
										<td><?php echo esc_html($record->old_role ?: '-'); ?></td>
										<td><?php echo esc_html($record->browser ?: '-'); ?></td>
										<td><?php echo esc_html($record->operating_system ?: '-'); ?></td>
										<td><?php echo esc_html($record->ip_address ?: '-'); ?></td>
										<td><?php echo esc_html($record->timezone ?: '-'); ?></td>
										<td><?php echo esc_html($record->country ?: '-'); ?></td>
										<td title="<?php echo esc_attr((string) $record->user_agent); ?>"><?php echo esc_html(wp_html_excerpt((string) $record->user_agent, 80, '...') ?: '-'); ?></td>
										<td><?php echo esc_html($this->format_duration($record)); ?></td>
										<td><?php echo esc_html($this->human_time($record->last_seen_at)); ?></td>
										<td><?php echo esc_html($this->format_date($record->login_at)); ?></td>
										<td><?php echo esc_html($this->format_date($record->logout_at)); ?></td>
										<td><?php echo esc_html($this->format_status($record->status)); ?></td>
									</tr>
								<?php endforeach; ?>
							<?php else : ?>
								<tr><td colspan="17"><?php esc_html_e('No login history found.', 'simple-login-history'); ?></td></tr>
							<?php endif; ?>
						</tbody>
					</table>
				</div>
				<div class="tablenav bottom">
					<?php $this->pagination($page, $total_pages, $total, $search, $status, $source, $order_by, $order); ?>
				</div>
			</form>
		</div>
		<style>
			.slh-table-wrap { clear: both; overflow-x: auto; width: 100%; border: 1px solid #c3c4c7; background: #fff; }
			.slh-login-table { border: 0; min-width: 1900px; table-layout: auto; }
			.slh-login-table .column-cb { width: 40px; }
			.slh-login-table th, .slh-login-table td { white-space: nowrap; vertical-align: top; }
			.slh-login-table th:nth-child(2), .slh-login-table td:nth-child(2) { width: 95px; }
			.slh-login-table th:nth-child(3), .slh-login-table td:nth-child(3) { width: 75px; }
			.slh-login-table th:nth-child(4), .slh-login-table td:nth-child(4) { min-width: 170px; }
			.slh-login-table th:nth-child(7), .slh-login-table td:nth-child(7) { min-width: 150px; }
			.slh-login-table th:nth-child(8), .slh-login-table td:nth-child(8) { min-width: 150px; }
			.slh-login-table th:nth-child(12), .slh-login-table td:nth-child(12) { min-width: 300px; max-width: 420px; overflow: hidden; text-overflow: ellipsis; }
			.slh-login-table th:nth-child(15), .slh-login-table td:nth-child(15),
			.slh-login-table th:nth-child(16), .slh-login-table td:nth-child(16) { min-width: 180px; }
		</style>
		<?php
	}

	public function render_settings_page(): void {
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('You do not have permission to manage login history settings.', 'simple-login-history'));
		}

		$options = $this->options();
		$roles = wp_roles()->roles;

		?>
		<div class="wrap">
			<h1><?php esc_html_e('Login History Settings', 'simple-login-history'); ?></h1>
			<?php if (!empty($_GET['settings-updated'])) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e('Login history settings saved.', 'simple-login-history'); ?></p></div>
			<?php endif; ?>
			<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
				<input type="hidden" name="action" value="slh_save_settings" />
				<?php wp_nonce_field('slh_save_settings', 'slh_nonce'); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e('Login Sources', 'simple-login-history'); ?></th>
						<td>
							<label>
								<input type="checkbox" name="track_wordpress_logins" value="1" <?php checked((int) $options['track_wordpress_logins'], 1); ?> />
								<?php esc_html_e('Track WordPress admin/site logins.', 'simple-login-history'); ?>
							</label><br />
							<label>
								<input type="checkbox" name="track_app_logins" value="1" <?php checked((int) $options['track_app_logins'], 1); ?> />
								<?php esc_html_e('Track AskBruno app logins from the LL706 Auth API.', 'simple-login-history'); ?>
							</label>
							<p class="description"><?php esc_html_e('Disable either source if you only want one type of login in the report.', 'simple-login-history'); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e('IP Address Control', 'simple-login-history'); ?></th>
						<td>
							<label>
								<input type="checkbox" name="store_ip" value="1" <?php checked((int) $options['store_ip'], 1); ?> />
								<?php esc_html_e('Store IP addresses with login records.', 'simple-login-history'); ?>
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e('Track Specific Roles', 'simple-login-history'); ?></th>
						<td><?php $this->role_checkboxes('track_roles', $options['track_roles'], $roles); ?>
							<p class="description"><?php esc_html_e('Leave all unchecked to track every role. Failed logins are always tracked because WordPress does not know the role yet.', 'simple-login-history'); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e('Auto Logout', 'simple-login-history'); ?></th>
						<td>
							<input type="number" min="0" max="1440" name="auto_logout_minutes" value="<?php echo esc_attr((int) $options['auto_logout_minutes']); ?>" class="small-text" />
							<?php esc_html_e('minutes of inactivity. Use 0 to disable.', 'simple-login-history'); ?>
							<p><?php esc_html_e('Roles affected by auto logout:', 'simple-login-history'); ?></p>
							<?php $this->role_checkboxes('auto_logout_roles', $options['auto_logout_roles'], $roles); ?>
							<p class="description"><?php esc_html_e('Leave all unchecked to apply auto logout to every role.', 'simple-login-history'); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e('Auto Delete Old Records', 'simple-login-history'); ?></th>
						<td>
							<input type="number" min="0" max="3650" name="auto_delete_days" value="<?php echo esc_attr((int) $options['auto_delete_days']); ?>" class="small-text" />
							<?php esc_html_e('days. Use 0 to keep records until manually deleted.', 'simple-login-history'); ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e('Email Alerts', 'simple-login-history'); ?></th>
						<td>
							<label><input type="checkbox" name="email_success" value="1" <?php checked((int) $options['email_success'], 1); ?> /> <?php esc_html_e('Successful logins', 'simple-login-history'); ?></label><br />
							<label><input type="checkbox" name="email_failed" value="1" <?php checked((int) $options['email_failed'], 1); ?> /> <?php esc_html_e('Failed logins', 'simple-login-history'); ?></label>
							<p>
								<label for="slh-email-to"><?php esc_html_e('Send to:', 'simple-login-history'); ?></label>
								<input type="email" id="slh-email-to" name="email_to" value="<?php echo esc_attr((string) $options['email_to']); ?>" class="regular-text" />
							</p>
							<p><?php esc_html_e('Successful login alert roles:', 'simple-login-history'); ?></p>
							<?php $this->role_checkboxes('email_roles', $options['email_roles'], $roles); ?>
							<p class="description"><?php esc_html_e('Leave all unchecked to alert on every tracked successful login. Failed login alerts do not use role filtering.', 'simple-login-history'); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e('CSV Separator', 'simple-login-history'); ?></th>
						<td>
							<select name="csv_separator">
								<option value="," <?php selected($options['csv_separator'], ','); ?>><?php esc_html_e('Comma', 'simple-login-history'); ?></option>
								<option value=";" <?php selected($options['csv_separator'], ';'); ?>><?php esc_html_e('Semicolon', 'simple-login-history'); ?></option>
								<option value="tab" <?php selected($options['csv_separator'], 'tab'); ?>><?php esc_html_e('Tab', 'simple-login-history'); ?></option>
							</select>
						</td>
					</tr>
				</table>
				<?php submit_button(__('Save Settings', 'simple-login-history')); ?>
			</form>
		</div>
		<?php
	}

	public function save_settings(): void {
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('You do not have permission to manage login history settings.', 'simple-login-history'));
		}

		$nonce = sanitize_text_field(wp_unslash($_POST['slh_nonce'] ?? ''));
		if (!wp_verify_nonce($nonce, 'slh_save_settings')) {
			wp_die(esc_html__('Invalid settings request.', 'simple-login-history'));
		}

		$options = [
			'store_ip' => isset($_POST['store_ip']) ? 1 : 0,
			'track_wordpress_logins' => isset($_POST['track_wordpress_logins']) ? 1 : 0,
			'track_app_logins' => isset($_POST['track_app_logins']) ? 1 : 0,
			'track_roles' => $this->sanitize_roles($_POST['track_roles'] ?? []),
			'auto_logout_minutes' => min(1440, absint($_POST['auto_logout_minutes'] ?? 0)),
			'auto_logout_roles' => $this->sanitize_roles($_POST['auto_logout_roles'] ?? []),
			'auto_delete_days' => min(3650, absint($_POST['auto_delete_days'] ?? 0)),
			'email_success' => isset($_POST['email_success']) ? 1 : 0,
			'email_failed' => isset($_POST['email_failed']) ? 1 : 0,
			'email_roles' => $this->sanitize_roles($_POST['email_roles'] ?? []),
			'email_to' => sanitize_email(wp_unslash($_POST['email_to'] ?? get_option('admin_email'))),
			'csv_separator' => $this->sanitize_csv_separator($_POST['csv_separator'] ?? ','),
		];

		if (!is_email($options['email_to'])) {
			$options['email_to'] = get_option('admin_email');
		}

		update_option(self::OPTION_NAME, $options);
		wp_safe_redirect(admin_url('admin.php?page=simple-login-history-settings&settings-updated=1'));
		exit;
	}

	public function export_csv(): void {
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('You do not have permission to export login history.', 'simple-login-history'));
		}

		$nonce = sanitize_text_field(wp_unslash($_GET['_wpnonce'] ?? ''));
		if (!wp_verify_nonce($nonce, 'slh_export')) {
			wp_die(esc_html__('Invalid export request.', 'simple-login-history'));
		}

		$search = sanitize_text_field(wp_unslash($_GET['s'] ?? ''));
		$status = sanitize_key($_GET['status'] ?? '');
		$source = $this->sanitize_source($_GET['source'] ?? '');
		$order_by = $this->sanitize_order_by($_GET['orderby'] ?? 'login_at');
		$order = ('asc' === strtolower((string) ($_GET['order'] ?? 'desc'))) ? 'ASC' : 'DESC';
		$this->refresh_app_login_statuses();
		$rows = $this->get_records(1, 50000, $search, $status, $source, $order_by, $order);
		$separator = $this->csv_separator();

		nocache_headers();
		header('Content-Type: text/csv; charset=utf-8');
		header('Content-Disposition: attachment; filename=simple-login-history-' . gmdate('Y-m-d') . '.csv');

		$output = fopen('php://output', 'w');
		fputcsv($output, ['Source', 'User ID', 'Username', 'Role', 'Old Role', 'Browser', 'Operating System', 'IP Address', 'Timezone', 'Country', 'User Agent', 'Duration', 'Last Seen', 'Login', 'Logout', 'Login Status'], $separator);

		foreach ($rows as $record) {
			fputcsv(
				$output,
				$this->csv_row([
					$this->format_source($record->source ?? 'wordpress'),
					$record->user_id ?: '',
					$record->username,
					$record->role,
					$record->old_role,
					$record->browser,
					$record->operating_system,
					$record->ip_address,
					$record->timezone,
					$record->country,
					$record->user_agent,
					$this->format_duration($record),
					$this->human_time($record->last_seen_at),
					$this->format_date($record->login_at),
					$this->format_date($record->logout_at),
					$this->format_status($record->status),
				]),
				$separator
			);
		}

		fclose($output);
		exit;
	}

	private function handle_admin_actions(): void {
		if (!current_user_can('manage_options')) {
			return;
		}

		if (isset($_GET['slh_delete'], $_GET['_wpnonce'])) {
			$id = absint($_GET['slh_delete']);
			if ($id && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'slh_delete_' . $id)) {
				$this->delete_records([$id]);
				add_settings_error('simple_login_history', 'deleted', __('Login history entry deleted.', 'simple-login-history'), 'updated');
				settings_errors('simple_login_history');
			}
		}

		if ('POST' !== $_SERVER['REQUEST_METHOD']) {
			return;
		}

		$nonce = sanitize_text_field(wp_unslash($_POST['slh_nonce'] ?? ''));
		if (!wp_verify_nonce($nonce, 'slh_bulk_action')) {
			return;
		}

		$action = sanitize_key($_POST['action'] ?? '');
		if ('delete' !== $action) {
			return;
		}

		$ids = array_map('absint', (array) ($_POST['record_ids'] ?? []));
		$ids = array_filter($ids);

		if ($ids) {
			$this->delete_records($ids);
			add_settings_error('simple_login_history', 'deleted', __('Selected login history entries deleted.', 'simple-login-history'), 'updated');
			settings_errors('simple_login_history');
		}
	}

	private function delete_records(array $ids): void {
		global $wpdb;

		$ids = array_values(array_filter(array_map('absint', $ids)));
		if (!$ids) {
			return;
		}

		$placeholders = implode(',', array_fill(0, count($ids), '%d'));
		$wpdb->query($wpdb->prepare("DELETE FROM " . self::table_name() . " WHERE id IN ({$placeholders})", $ids));
	}

	private function get_records(int $page, int $per_page, string $search, string $status, string $source, string $order_by, string $order): array {
		global $wpdb;

		$where = $this->where_sql($search, $status, $source);
		$offset = ($page - 1) * $per_page;
		$table = self::table_name();

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} {$where['sql']} ORDER BY {$order_by} {$order} LIMIT %d OFFSET %d",
				array_merge($where['values'], [$per_page, $offset])
			)
		);
	}

	private function count_records(string $search, string $status, string $source): int {
		global $wpdb;

		$where = $this->where_sql($search, $status, $source);
		$table = self::table_name();

		$sql = "SELECT COUNT(*) FROM {$table} {$where['sql']}";
		if ($where['values']) {
			$sql = $wpdb->prepare($sql, $where['values']);
		}

		return (int) $wpdb->get_var($sql);
	}

	private function where_sql(string $search, string $status, string $source): array {
		global $wpdb;

		$where = [];
		$values = [];

		if ('' !== $search) {
			$like = '%' . $wpdb->esc_like($search) . '%';
			$where[] = '(username LIKE %s OR ip_address LIKE %s OR user_agent LIKE %s OR browser LIKE %s OR operating_system LIKE %s OR source LIKE %s)';
			array_push($values, $like, $like, $like, $like, $like, $like);
		}

		if (in_array($status, ['logged_in', 'logged_out', 'failed', 'active', 'expired', 'invalidated'], true)) {
			$where[] = 'status = %s';
			$values[] = $status;
		}

		if (in_array($source, ['wordpress', 'app'], true)) {
			$where[] = 'source = %s';
			$values[] = $source;
		}

		return [
			'sql' => $where ? 'WHERE ' . implode(' AND ', $where) : '',
			'values' => $values,
		];
	}

	private function sanitize_order_by($order_by): string {
		$allowed = ['user_id', 'username', 'ip_address', 'login_at', 'logout_at', 'status', 'source'];
		$order_by = sanitize_key((string) $order_by);

		return in_array($order_by, $allowed, true) ? $order_by : 'login_at';
	}

	private function sanitize_source($source): string {
		$source = sanitize_key((string) $source);

		return in_array($source, ['wordpress', 'app'], true) ? $source : '';
	}

	private function header_cell(string $key, string $label, string $current_order_by, string $current_order): void {
		$next_order = ('ASC' === $current_order) ? 'desc' : 'asc';
		$url = add_query_arg(
			[
				'orderby' => $key,
				'order' => $next_order,
				'paged' => 1,
			]
		);
		$class = $current_order_by === $key ? 'sorted ' . strtolower($current_order) : 'sortable desc';

		printf(
			'<th scope="col" class="manage-column column-%1$s %2$s"><a href="%3$s"><span>%4$s</span><span class="sorting-indicators"><span class="sorting-indicator asc"></span><span class="sorting-indicator desc"></span></span></a></th>',
			esc_attr($key),
			esc_attr($class),
			esc_url($url),
			esc_html($label)
		);
	}

	private function pagination(int $page, int $total_pages, int $total, string $search, string $status, string $source, string $order_by, string $order): void {
		$base_args = [
			'page' => 'simple-login-history',
			's' => $search,
			'status' => $status,
			'source' => $source,
			'orderby' => $order_by,
			'order' => strtolower($order),
		];

		echo '<div class="tablenav-pages">';
		printf('<span class="displaying-num">%s</span>', esc_html(sprintf(_n('%s item', '%s items', $total, 'simple-login-history'), number_format_i18n($total))));
		echo paginate_links(
			[
				'base' => add_query_arg(array_merge($base_args, ['paged' => '%#%'])),
				'format' => '',
				'prev_text' => '&lsaquo;',
				'next_text' => '&rsaquo;',
				'total' => $total_pages,
				'current' => $page,
			]
		);
		echo '</div>';
	}

	private function status_filter_options(string $current, string $source): string {
		$base = remove_query_arg(['status', 'paged']);
		$options = [
			'' => __('All statuses', 'simple-login-history'),
			'logged_in' => __('Logged In', 'simple-login-history'),
			'logged_out' => __('Logged Out', 'simple-login-history'),
			'active' => __('Active', 'simple-login-history'),
			'expired' => __('Expired', 'simple-login-history'),
			'invalidated' => __('Invalidated', 'simple-login-history'),
			'failed' => __('Failed', 'simple-login-history'),
		];

		$html = '';
		foreach ($options as $status => $label) {
			$args = ['paged' => 1];
			if ('' !== $status) {
				$args['status'] = $status;
			}
			if ('' !== $source) {
				$args['source'] = $source;
			}
			$url = add_query_arg($args, $base);
			$html .= sprintf(
				'<option value="%s" %s>%s</option>',
				esc_url($url),
				selected($current, $status, false),
				esc_html($label)
			);
		}

		return $html;
	}

	private function source_filter_options(string $current, string $status): string {
		$base = remove_query_arg(['source', 'paged']);
		$options = [
			'' => __('All sources', 'simple-login-history'),
			'wordpress' => __('WordPress', 'simple-login-history'),
			'app' => __('App', 'simple-login-history'),
		];

		$html = '';
		foreach ($options as $source => $label) {
			$args = ['paged' => 1];
			if ('' !== $source) {
				$args['source'] = $source;
			}
			if ('' !== $status) {
				$args['status'] = $status;
			}
			$url = add_query_arg($args, $base);
			$html .= sprintf(
				'<option value="%s" %s>%s</option>',
				esc_url($url),
				selected($current, $source, false),
				esc_html($label)
			);
		}

		return $html;
	}

	private function delete_url(int $id): string {
		return wp_nonce_url(
			add_query_arg(['slh_delete' => $id]),
			'slh_delete_' . $id
		);
	}

	private function export_url(string $search, string $status, string $source, string $order_by, string $order): string {
		return wp_nonce_url(
			add_query_arg(
				[
					'action' => 'slh_export',
					's' => $search,
					'status' => $status,
					'source' => $source,
					'orderby' => $order_by,
					'order' => strtolower($order),
				],
				admin_url('admin-post.php')
			),
			'slh_export'
		);
	}

	private function role_checkboxes(string $name, array $selected, array $roles): void {
		foreach ($roles as $role => $details) {
			printf(
				'<label style="display:inline-block;margin:0 16px 8px 0;"><input type="checkbox" name="%1$s[]" value="%2$s" %3$s /> %4$s</label>',
				esc_attr($name),
				esc_attr($role),
				checked(in_array($role, $selected, true), true, false),
				esc_html(translate_user_role($details['name'] ?? $role))
			);
		}
	}

	private function sanitize_roles($roles): array {
		$roles = array_map('sanitize_key', (array) $roles);
		$allowed = array_keys(wp_roles()->roles);

		return array_values(array_intersect($roles, $allowed));
	}

	private function sanitize_csv_separator($separator): string {
		$separator = (string) sanitize_text_field(wp_unslash($separator));

		return in_array($separator, [',', ';', 'tab'], true) ? $separator : ',';
	}

	private function csv_separator(): string {
		return 'tab' === $this->options()['csv_separator'] ? "\t" : $this->options()['csv_separator'];
	}

	private function csv_row(array $row): array {
		return array_map([$this, 'csv_cell'], $row);
	}

	private function csv_cell($value): string {
		$value = (string) $value;

		if ('' !== $value && preg_match('/^[=+\-@]/', ltrim($value))) {
			return "'" . $value;
		}

		return $value;
	}

	private function should_track_user(WP_User $user, string $option_key): bool {
		$roles = (array) ($this->options()[$option_key] ?? []);
		if (!$roles) {
			return true;
		}

		return (bool) array_intersect($roles, (array) $user->roles);
	}

	private function maybe_send_email_alert(string $type, ?WP_User $user, string $username): void {
		$options = $this->options();
		if ('success' === $type && empty($options['email_success'])) {
			return;
		}

		if ('failed' === $type && empty($options['email_failed'])) {
			return;
		}

		if ('success' === $type && $user instanceof WP_User && !$this->should_track_user($user, 'email_roles')) {
			return;
		}

		$to = (string) $options['email_to'];
		if (!is_email($to)) {
			return;
		}

		$subject = sprintf('[%s] %s login for %s', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES), ucfirst($type), $username);
		$message = sprintf(
			"Login status: %s\nUsername: %s\nUser ID: %s\nIP Address: %s\nBrowser: %s\nOperating System: %s\nTime: %s\nUser Agent: %s\n",
			'success' === $type ? 'Successful' : 'Failed',
			$username,
			$user instanceof WP_User ? (string) $user->ID : '-',
			$this->options()['store_ip'] ? $this->get_ip_address() : '-',
			$this->detect_browser($this->get_user_agent()) ?: '-',
			$this->detect_operating_system($this->get_user_agent()) ?: '-',
			wp_date(get_option('date_format') . ' ' . get_option('time_format'), current_time('timestamp')),
			$this->get_user_agent() ?: '-'
		);

		wp_mail($to, $subject, $message);
	}

	private function get_user_roles(WP_User $user): string {
		if (!$user->roles) {
			return '';
		}

		$wp_roles = wp_roles();
		$role_names = [];

		foreach ($user->roles as $role) {
			$role_names[] = translate_user_role($wp_roles->roles[$role]['name'] ?? $role);
		}

		return implode(', ', $role_names);
	}

	private function get_ip_address(): string {
		$headers = [
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_REAL_IP',
			'HTTP_X_FORWARDED_FOR',
			'REMOTE_ADDR',
		];

		foreach ($headers as $header) {
			if (empty($_SERVER[$header])) {
				continue;
			}

			$value = sanitize_text_field(wp_unslash($_SERVER[$header]));
			$parts = array_map('trim', explode(',', $value));
			$ip = $parts[0] ?? '';

			if (filter_var($ip, FILTER_VALIDATE_IP)) {
				return $ip;
			}
		}

		return '';
	}

	private function get_site_timezone(): string {
		$timezone = wp_timezone_string();
		if ($timezone) {
			return $timezone;
		}

		$offset = (float) get_option('gmt_offset', 0);
		if (0.0 === $offset) {
			return 'UTC';
		}

		$hours = (int) $offset;
		$minutes = (int) round(abs($offset - $hours) * 60);

		return sprintf('UTC%+03d:%02d', $hours, $minutes);
	}

	private function get_user_agent(): string {
		return isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_textarea_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
	}

	private function detect_browser(string $user_agent): string {
		if (preg_match('/Edg\/([0-9.]+)/', $user_agent, $matches)) {
			return 'Edge (' . $matches[1] . ')';
		}

		if (preg_match('/Chrome\/([0-9.]+)/', $user_agent, $matches) && false === stripos($user_agent, 'Chromium')) {
			return 'Chrome (' . $matches[1] . ')';
		}

		if (preg_match('/Version\/([0-9.]+).*Safari\//', $user_agent, $matches)) {
			return 'Safari (' . $matches[1] . ')';
		}

		if (preg_match('/Firefox\/([0-9.]+)/', $user_agent, $matches)) {
			return 'Firefox (' . $matches[1] . ')';
		}

		if (preg_match('/MSIE ([0-9.]+)|Trident\/.*rv:([0-9.]+)/', $user_agent, $matches)) {
			return 'Internet Explorer (' . ($matches[1] ?: $matches[2]) . ')';
		}

		if (preg_match('/okhttp\/([0-9.]+)/i', $user_agent, $matches)) {
			return 'okhttp (' . $matches[1] . ')';
		}

		return '';
	}

	private function detect_operating_system(string $user_agent): string {
		$checks = [
			'iPhone' => 'iPhone',
			'iPad' => 'iPad',
			'Android' => 'Java/Android',
			'Windows' => 'Windows',
			'Mac OS X' => 'Apple',
			'Macintosh' => 'Apple',
			'Linux' => 'Linux',
			'Darwin' => 'Darwin',
		];

		foreach ($checks as $needle => $label) {
			if (false !== stripos($user_agent, $needle)) {
				return $label;
			}
		}

		return '';
	}

	private function format_duration(object $record): string {
		if ('failed' === $record->status) {
			return '1 second';
		}

		$start = $this->local_mysql_timestamp($record->login_at);
		$end_value = $record->logout_at ?: $record->last_seen_at;
		$end = $end_value ? $this->local_mysql_timestamp($end_value) : current_time('timestamp');

		if (!$start || !$end || $end <= $start) {
			return '1 second';
		}

		return human_time_diff($start, $end);
	}

	private function human_time($date): string {
		if (!$date) {
			return '-';
		}

		$time = $this->local_mysql_timestamp($date);
		if (!$time) {
			return '-';
		}

		return sprintf(__('%s ago', 'simple-login-history'), human_time_diff($time, current_time('timestamp')));
	}

	private function format_date($date): string {
		if (!$date) {
			return '-';
		}

		$date = (string) $date;
		if (!$this->local_mysql_timestamp($date)) {
			return '-';
		}

		return mysql2date(get_option('date_format') . ' ' . get_option('time_format'), $date);
	}

	private function local_mysql_timestamp($date): int {
		if (!$date) {
			return 0;
		}

		try {
			$date_time = new DateTimeImmutable((string) $date, wp_timezone());
		} catch (Exception $exception) {
			return 0;
		}

		return $date_time->getTimestamp();
	}

	private function format_status(string $status): string {
		$labels = [
			'logged_in' => __('Logged In', 'simple-login-history'),
			'logged_out' => __('Logged Out', 'simple-login-history'),
			'active' => __('Active', 'simple-login-history'),
			'expired' => __('Expired', 'simple-login-history'),
			'invalidated' => __('Invalidated', 'simple-login-history'),
			'failed' => __('Failed', 'simple-login-history'),
		];

		return $labels[$status] ?? $status;
	}

	private function format_source(string $source): string {
		$labels = [
			'wordpress' => __('WordPress', 'simple-login-history'),
			'app' => __('App', 'simple-login-history'),
		];

		return $labels[$source] ?? $source;
	}

	private function set_session_cookie(string $session_token): void {
		if (headers_sent()) {
			return;
		}

		setcookie(
			self::SESSION_COOKIE,
			$session_token,
			[
				'expires' => time() + YEAR_IN_SECONDS,
				'path' => COOKIEPATH ?: '/',
				'domain' => COOKIE_DOMAIN,
				'secure' => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			]
		);

		$_COOKIE[self::SESSION_COOKIE] = $session_token;
	}

	private function get_session_cookie(): string {
		if (empty($_COOKIE[self::SESSION_COOKIE])) {
			return '';
		}

		$token = sanitize_text_field(wp_unslash($_COOKIE[self::SESSION_COOKIE]));

		return preg_match('/^[A-Za-z0-9]{32}$/', $token) ? $token : '';
	}

	private function clear_session_cookie(): void {
		if (!headers_sent()) {
			setcookie(
				self::SESSION_COOKIE,
				'',
				[
					'expires' => time() - HOUR_IN_SECONDS,
					'path' => COOKIEPATH ?: '/',
					'domain' => COOKIE_DOMAIN,
					'secure' => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				]
			);
		}

		unset($_COOKIE[self::SESSION_COOKIE]);
	}
}

register_activation_hook(__FILE__, ['Simple_Login_History', 'activate']);
register_uninstall_hook(__FILE__, ['Simple_Login_History', 'uninstall']);

Simple_Login_History::instance();
