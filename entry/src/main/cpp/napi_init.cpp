#include "tun_reader.h"
#include "dns_handler.h"

#include <napi/native_api.h>
#include <string>
#include <vector>

static napi_value StartTun(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    int32_t tun_fd = 0;
    napi_get_value_int32(env, args[0], &tun_fd);
    tun_start(tun_fd);

    napi_value undefined;
    napi_get_undefined(env, &undefined);
    return undefined;
}

static napi_value StopTun(napi_env env, napi_callback_info info) {
    tun_stop();
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    return undefined;
}

static napi_value SetDomains(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    uint32_t len = 0;
    napi_get_array_length(env, args[0], &len);

    std::vector<std::string> domains;
    for (uint32_t i = 0; i < len; i++) {
        napi_value elem;
        napi_get_element(env, args[0], i, &elem);
        size_t str_len = 0;
        napi_get_value_string_utf8(env, elem, nullptr, 0, &str_len);
        std::string domain(str_len + 1, '\0');
        napi_get_value_string_utf8(env, elem, domain.data(), str_len + 1, &str_len);
        domain.resize(str_len);
        domains.push_back(domain);
    }

    dns_set_domains(domains);

    napi_value undefined;
    napi_get_undefined(env, &undefined);
    return undefined;
}

static napi_value SetStatsPath(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    size_t str_len = 0;
    napi_get_value_string_utf8(env, args[0], nullptr, 0, &str_len);
    std::string path(str_len + 1, '\0');
    napi_get_value_string_utf8(env, args[0], path.data(), str_len + 1, &str_len);
    path.resize(str_len);
    tun_set_stats_path(path.c_str());

    napi_value undefined;
    napi_get_undefined(env, &undefined);
    return undefined;
}

static napi_value GetStats(napi_env env, napi_callback_info info) {
    napi_value obj;
    napi_create_object(env, &obj);

    napi_value running;
    napi_get_boolean(env, tun_is_running(), &running);
    napi_set_named_property(env, obj, "running", running);

    napi_value queries;
    napi_create_int64(env, static_cast<int64_t>(tun_dns_queries()), &queries);
    napi_set_named_property(env, obj, "dnsQueries", queries);

    napi_value accelerated;
    napi_create_int64(env, static_cast<int64_t>(tun_accelerated_queries()), &accelerated);
    napi_set_named_property(env, obj, "acceleratedQueries", accelerated);

    return obj;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor desc[] = {
        {"startTun", nullptr, StartTun, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"stopTun", nullptr, StopTun, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setDomains", nullptr, SetDomains, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setStatsPath", nullptr, SetStatsPath, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"getStats", nullptr, GetStats, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}

static napi_module biuModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "biu",
    .nm_priv = nullptr,
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterBiuModule() {
    napi_module_register(&biuModule);
}
