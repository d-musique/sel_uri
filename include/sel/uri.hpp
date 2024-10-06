// The SEL extension library
// Free software published under the MIT license.

#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <stdint.h>

namespace sel
{

class uri_builder;

class uri
{
public:
    enum class escape_mode;
    struct attribute;

    uri() noexcept = default;
    uri(uri &&) noexcept = default;
    uri &operator=(uri &&) noexcept = default;
    uri(const uri &);
    uri &operator=(const uri &);

    static uri parse(std::string_view string);

    bool valid() const noexcept { return flags() & uri_flag_is_valid; }
    explicit operator bool() const noexcept { return flags() & uri_flag_is_valid; }

    bool has_scheme() const noexcept { return flags() & uri_flag_has_scheme; }
    bool has_authority() const noexcept { return flags() & uri_flag_has_authority; }
    bool has_username() const noexcept { return flags() & uri_flag_has_username; }
    bool has_password() const noexcept { return flags() & uri_flag_has_password; }
    bool has_host() const noexcept { return flags() & uri_flag_has_host; }
    bool has_port() const noexcept { return flags() & uri_flag_has_port; }
    bool has_query() const noexcept { return flags() & uri_flag_has_query; }
    bool has_fragment() const noexcept { return flags() & uri_flag_has_fragment; }

    const std::string &scheme() const noexcept;
    const std::string &username() const noexcept;
    const std::string &password() const noexcept;
    const std::string &host() const noexcept;
    uint16_t port() const noexcept;
    const std::string &path() const noexcept;
    const std::vector<attribute> &query() const noexcept;
    const std::string &fragment() const noexcept;

    enum class path_style { generic, dos };

    static uri make_file_uri(std::string_view path, path_style style);
    static uri make_native_file_uri(std::string_view path);
    std::string file_path(path_style style) const;
    std::string native_file_path() const;

    static void escape(std::string_view string, escape_mode mode, void *ctx, void (*write)(void *, const char *, size_t));
    static bool unescape(std::string_view string, escape_mode mode, void *ctx, void (*write)(void *, const char *, size_t));
    static void escape_to_string(std::string_view string, escape_mode mode, std::string *result);
    static bool unescape_to_string(std::string_view string, escape_mode mode, std::string *result);

    void format(void *ctx, void (*write)(void *, const char *, size_t)) const;
    std::string to_string() const;

    size_t hash_code(size_t seed = 0) const noexcept;
    int compare(const uri &other) const noexcept;
    bool operator<(const uri &other) const noexcept { return compare(other) < 0; }
    bool operator<=(const uri &other) const noexcept { return compare(other) <= 0; }
    bool operator>(const uri &other) const noexcept { return compare(other) > 0; }
    bool operator>=(const uri &other) const noexcept { return compare(other) >= 0; }
    bool operator==(const uri &other) const noexcept;
    bool operator!=(const uri &other) const noexcept { return !operator==(other); }
#if __cplusplus >= 202002L
    int operator<=>(const uri &other) const noexcept { return compare(other); }
#endif

    enum class escape_mode
    {
        all,
        query,
        path,
        path_no_colon,
    };

    struct attribute
    {
        std::string key;
        std::string value;
        bool has_value = false;
    };

private:
    enum {
        uri_flag_is_valid = (1 << 0),
        uri_flag_has_scheme = (1 << 1),
        uri_flag_has_authority = (1 << 2),
        uri_flag_has_username = (1 << 3),
        uri_flag_has_password = (1 << 4),
        uri_flag_has_host = (1 << 5),
        uri_flag_has_port = (1 << 6),
        uri_flag_has_query = (1 << 7),
        uri_flag_has_fragment = (1 << 8),
    };

    [[gnu::const]] int flags() const noexcept;

    struct internal;
    struct internal_delete { void operator()(internal *x) const noexcept; };
    std::unique_ptr<internal, internal_delete> m_priv;

    friend class uri_builder;
};

class uri_builder
{
public:
    uri_builder();
    void set_scheme(std::string scheme);
    void prefer_authority(bool prefer);
    void set_username(std::string username);
    void set_password(std::string password);
    void set_host(std::string host);
    void set_port(int port);
    void set_path(std::string path);
    void add_query_attribute(std::string key);
    void add_query_attribute(std::string key, std::string value);
    void set_fragment(std::string fragment);
    uri build();

private:
    struct internal;
    struct internal_delete { void operator()(internal *x) const noexcept; };
    std::unique_ptr<internal, internal_delete> m_priv;
};

}
// namespace sel

template <>
struct std::hash<sel::uri>
{
    size_t operator()(const sel::uri &x) const noexcept
    {
        return x.hash_code();
    }
};
