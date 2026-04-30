export const CONNECT_VERSION3 = 3;
export const arch_generic = 1;

export const op_connect = 1;
export const op_accept = 3;
export const op_reject = 4;
export const op_disconnect = 6;
export const op_response = 9;
export const op_attach = 19;
export const op_create = 20;
export const op_detach = 21;
export const op_transaction = 29;
export const op_commit = 30;
export const op_rollback = 31;
export const op_create_blob = 34;
export const op_open_blob = 35;
export const op_get_segment = 36;
export const op_put_segment = 37;
export const op_cancel_blob = 38;
export const op_close_blob = 39;
export const op_commit_retaining = 50;
export const op_open_blob2 = 56;
export const op_create_blob2 = 57;
export const op_seek_blob = 61;
export const op_allocate_statement = 62;
export const op_execute = 63;
export const op_fetch = 65;
export const op_fetch_response = 66;
export const op_free_statement = 67;
export const op_prepare_statement = 68;
export const op_dummy = 71;
export const op_rollback_retaining = 86;
export const op_drop_database = 81;
export const op_cont_auth = 92;
export const op_ping = 93;
export const op_accept_data = 94;
export const op_cond_accept = 98;

export const ptype_batch_send = 3;
export const ptype_lazy_send = 5;

export const FB_PROTOCOL_FLAG = 0x8000;
export const PROTOCOL_VERSION13 = FB_PROTOCOL_FLAG | 13;
export const PROTOCOL_VERSION14 = FB_PROTOCOL_FLAG | 14;
export const PROTOCOL_VERSION15 = FB_PROTOCOL_FLAG | 15;
export const PROTOCOL_VERSION16 = FB_PROTOCOL_FLAG | 16;
export const PROTOCOL_VERSION17 = FB_PROTOCOL_FLAG | 17;
export const PROTOCOL_VERSION18 = FB_PROTOCOL_FLAG | 18;
export const PROTOCOL_VERSION19 = FB_PROTOCOL_FLAG | 19;
export const SUPPORTED_PROTOCOLS = [
  PROTOCOL_VERSION19,
  PROTOCOL_VERSION18,
  PROTOCOL_VERSION17,
  PROTOCOL_VERSION16,
  PROTOCOL_VERSION15,
  PROTOCOL_VERSION14,
  PROTOCOL_VERSION13,
];

export const CNCT_user = 1;
export const CNCT_host = 4;
export const CNCT_user_verification = 6;
export const CNCT_specific_data = 7;
export const CNCT_plugin_name = 8;
export const CNCT_login = 9;
export const CNCT_plugin_list = 10;
export const CNCT_client_crypt = 11;

export const WIRE_CRYPT_DISABLED = 0;
export const WIRE_CRYPT_ENABLED = 1;

export const isc_dpb_version1 = 1;
export const isc_dpb_version2 = 2;
export const isc_dpb_page_size = 4;
export const isc_dpb_user_name = 28;
export const isc_dpb_lc_ctype = 48;
export const isc_dpb_overwrite = 54;
export const isc_dpb_sql_dialect = 63;
export const isc_dpb_dummy_packet_interval = 58;
export const isc_dpb_utf8_filename = 77;
export const isc_dpb_specific_auth_data = 84;
export const isc_dpb_auth_plugin_list = 85;
export const isc_dpb_auth_plugin_name = 86;

export const isc_arg_end = 0;
export const isc_arg_gds = 1;
export const isc_arg_string = 2;
export const isc_arg_cstring = 3;
export const isc_arg_number = 4;
export const isc_arg_interpreted = 5;
export const isc_arg_warning = 18;

export const isc_info_sql_select = 4;
export const isc_info_sql_bind = 5;
export const isc_info_sql_describe_vars = 7;
export const isc_info_sql_describe_end = 8;
export const isc_info_sql_sqlda_seq = 9;
export const isc_info_sql_type = 11;
export const isc_info_sql_sub_type = 12;
export const isc_info_sql_scale = 13;
export const isc_info_sql_length = 14;
export const isc_info_sql_field = 16;
export const isc_info_sql_relation = 17;
export const isc_info_sql_owner = 18;
export const isc_info_sql_alias = 19;
export const isc_info_sql_stmt_type = 21;
export const isc_info_sql_relation_alias = 25;
export const isc_info_end = 1;
export const isc_info_truncated = 2;

export const isc_info_sql_stmt_select = 1;
export const isc_info_sql_stmt_select_for_upd = 12;

export const DSQL_drop = 2;

export const SQL_TEXT = 452;
export const SQL_VARYING = 448;
export const SQL_SHORT = 500;
export const SQL_LONG = 496;
export const SQL_DOUBLE = 480;
export const SQL_TIMESTAMP = 510;
export const SQL_BLOB = 520;
export const SQL_TYPE_TIME = 560;
export const SQL_TYPE_DATE = 570;
export const SQL_INT64 = 580;
export const SQL_BOOLEAN = 32764;

export const blr_text = 14;
export const blr_short = 7;
export const blr_long = 8;
export const blr_double = 27;
export const blr_timestamp = 35;
export const blr_varying = 37;
export const blr_sql_date = 12;
export const blr_sql_time = 13;
export const blr_int64 = 16;
export const blr_blob2 = 17;
export const blr_bool = 23;
export const blr_version5 = 5;
export const blr_eoc = 76;
export const blr_end = 255;
export const blr_begin = 2;
export const blr_message = 4;

export const AUTH_PLUGINS = ['Srp256', 'Srp', 'Legacy_Auth'] as const;
export type AuthPluginName = (typeof AUTH_PLUGINS)[number];
