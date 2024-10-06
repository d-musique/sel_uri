// -*- c++ -*- //

// The SEL extension library
// Free software published under the MIT license.

#include "sel/uri.hpp"
#include <string.h>

namespace sel
{

/*!rules:re2c:Common
    re2c:flags:tags = 1;
    re2c:yyfill:enable = 0;
    re2c:eof = 0;
    re2c:api = custom;
    re2c:api:style = free-form;
    re2c:define:YYCTYPE = int;
    re2c:define:YYPEEK       = "cursor < limit ? (unsigned char)*cursor : 0"; // "*cursor";
    re2c:define:YYSKIP       = "++cursor;";
    re2c:define:YYBACKUP     = "marker = cursor;";
    re2c:define:YYRESTORE    = "cursor = marker;";
    re2c:define:YYBACKUPCTX  = "ctxmarker = cursor;";
    re2c:define:YYRESTORECTX = "cursor = ctxmarker;";
    re2c:define:YYRESTORETAG = "cursor = ${tag};";
    re2c:define:YYLESSTHAN   = "limit - cursor < @@{len}";
    re2c:define:YYSTAGP      = "@@{tag} = cursor;";
    re2c:define:YYSTAGN      = "@@{tag} = NULL;";
    re2c:define:YYSHIFT      = "cursor += @@{shift};";
    re2c:define:YYSHIFTSTAG  = "@@{tag} += @@{shift};";
    any = .|"\n";
*/

struct uri::internal
{
    unsigned int m_flags = 0;
    std::string m_scheme;
    std::string m_username;
    std::string m_password;
    std::string m_host;
    uint16_t m_port = 0;
    std::string m_path;
    std::vector<attribute> m_query;
    std::string m_fragment;
    static bool parse_query(std::string_view string, std::vector<attribute> &qa);
    size_t hash_code(size_t seed) const noexcept;
    int compare(const internal &other) const noexcept;
    bool operator==(const internal &other) const noexcept;
};

uri::uri(const uri &other)
    : m_priv(other.m_priv ? new internal(*other.m_priv) : nullptr)
{
}

uri &uri::operator=(const uri &other)
{
    if (this != &other)
        m_priv.reset(other.m_priv ? new internal(*other.m_priv) : nullptr);
    return *this;
}

uri uri::parse(std::string_view string)
{
    uri uri;
    uri::internal *priv = new uri::internal;
    uri.m_priv.reset(priv);
    std::string_view authority_and_path;

    {
        const char *cursor = string.data();
        const char *limit = cursor + string.size();
        const char *marker [[maybe_unused]];
        const char *s1, *s2, *ap1, *ap2, *q1, *q2, *f1, *f2, *e1, *e2;
        /*!stags:re2c:URI format = 'const char *@@;\n'; */

/*!local:re2c:URI
  !use:Common;

Scheme = [a-zA-Z][a-zA-Z0-9+.-]*;
AuthorityAndPath = [^?#]*;
Query = [^#]*;
Fragment = any*;

(@s1 Scheme @s2 ":")? @ap1 AuthorityAndPath @ap2
("?" @q1 Query @q2)? ("#" @f1 Fragment @f2)? @e1 any* @e2
{
    if (e1 != e2)
        return {};

    if (s1)
    {
        priv->m_scheme.assign(s1, s2);
        priv->m_flags |= uri_flag_has_scheme;
    }

    if (q1)
    {
        if (!internal::parse_query(std::string_view(q1, q2 - q1), priv->m_query))
            return {};
        priv->m_flags |= uri_flag_has_query;
    }

    if (f1)
    {
        priv->m_fragment.assign(f1, f2);
        priv->m_flags |= uri_flag_has_fragment;
    }

    authority_and_path = std::string_view(ap1, ap2 - ap1);
    goto cont1;
}

any*
{
    return {};
}

$
{
    return {};
}

*/

    cont1: ;
    }

    {
        const char *cursor = authority_and_path.data();
        const char *limit = cursor + authority_and_path.size();
        const char *marker [[maybe_unused]];
        const char *u1, *u2, *x1, *x2, *h1, *h2, *o1, *o2, *p1, *p2, *e1, *e2;
        /*!stags:re2c:AuthorityAndPath format = 'const char *@@;\n'; */

/*!local:re2c:AuthorityAndPath
  !use:Common;

user = [^/@:]*;
password = [^/@]*;
host = ("[" [^\]]* "]") | ([^/:]+);
port = "0"* [0-9]{0,5};
path = "/" any*;

"//"
((@u1 user @u2 (":" @x1 password @x2)? "@")? @h1 host @h2 (":" @o1 port @o2)?)?
@p1 path? @p2 @e1 any* @e2
{
    if (e1 != e2)
        return {};
    priv->m_flags |= uri_flag_has_authority;

    if (u1)
    {
        if (!unescape_to_string(std::string_view(u1, u2 - u1), escape_mode::all, &priv->m_username))
            return {};
        priv->m_flags |= uri_flag_has_username;

        if (x1)
        {
            if (!unescape_to_string(std::string_view(x1, x2 - x1), escape_mode::all, &priv->m_password))
                return {};
            priv->m_flags |= uri_flag_has_password;
        }
    }

    if (h1)
    {
        if (!unescape_to_string(std::string_view(h1, h2 - h1), escape_mode::all, &priv->m_host))
            return {};
        priv->m_flags |= uri_flag_has_host;
    }

    if (!unescape_to_string(std::string_view(p1, p2 - p1), escape_mode::path, &priv->m_path))
        return {};

    if (o1)
    {
        unsigned int port = 0;
        for (const char *pp = o1; pp != o2; pp++)
            port = port * 10 + (*pp - '0');
        if (port >= 65536)
            return {};
        priv->m_port = (uint16_t)port;
        priv->m_flags |= uri_flag_has_port;
    }

    goto cont2;
}

@p1 any* @p2
{
    if (!unescape_to_string(std::string_view(p1, p2 - p1), escape_mode::path, &priv->m_path))
        return {};

    goto cont2;
}

$
{
    return {};
}

*/

    cont2: ;
    }

    priv->m_flags |= uri_flag_is_valid;
    return uri;
}

const std::string &uri::scheme() const noexcept
{
    if (!m_priv)
    {
        static std::string empty;
        return empty;
    }

    return m_priv->m_scheme;
}

const std::string &uri::username() const noexcept
{
    if (!m_priv)
    {
        static std::string empty;
        return empty;
    }

    return m_priv->m_username;
}

const std::string &uri::password() const noexcept
{
    if (!m_priv)
    {
        static std::string empty;
        return empty;
    }

    return m_priv->m_password;
}

const std::string &uri::host() const noexcept
{
    if (!m_priv)
    {
        static std::string empty;
        return empty;
    }

    return m_priv->m_host;
}

uint16_t uri::port() const noexcept
{
    return m_priv ? m_priv->m_port : 0;
}

const std::string &uri::path() const noexcept
{
    if (!m_priv)
    {
        static std::string empty;
        return empty;
    }

    return m_priv->m_path;
}

const std::vector<uri::attribute> &uri::query() const noexcept
{
    if (!m_priv)
    {
        static std::vector<uri::attribute> empty;
        return empty;
    }

    return m_priv->m_query;
}

const std::string &uri::fragment() const noexcept
{
    if (!m_priv)
    {
        static std::string empty;
        return empty;
    }

    return m_priv->m_fragment;
}

int uri::flags() const noexcept
{
    return m_priv ? m_priv->m_flags : 0;
}

static bool path_has_dos_drive(std::string_view path)
{
    if (path.length() < 2 || path[1] != ':')
        return false;
    char dl = path.front();
    return (dl >= 'a' && dl <= 'z') || (dl >= 'A' && dl <= 'Z');
};

static bool path_is_authority_compatible(std::string_view path)
{
    return path.empty() || path.front() == '/';
}

static bool path_is_authority_required(std::string_view path)
{
    return path.size() >= 2 && path[0] == '/' && path[1] == '/';
}

static std::string path_from_file_path(std::string_view fs_path, uri::path_style style)
{
    if (style == uri::path_style::dos)
    {
        std::string dos_path;
        if (path_has_dos_drive(fs_path))
        {
            dos_path.reserve(1 + fs_path.size());
            dos_path.push_back('/');
            dos_path.append(fs_path);
        }
        else
        {
            dos_path.assign(fs_path);
        }
        for (char &c : dos_path) if (c == '\\') c = '/';
        return dos_path;
    }
    else
    {
        return std::string(fs_path);
    }
}

uri uri::make_file_uri(std::string_view path, path_style style)
{
    uri uri;
    internal *priv = new internal;
    uri.m_priv.reset(priv);

    priv->m_scheme.assign("file");
    priv->m_flags |= uri_flag_has_scheme;

    priv->m_path = path_from_file_path(path, style);

    if (path_is_authority_compatible(priv->m_path))
        priv->m_flags |= uri_flag_has_authority;

    priv->m_flags |= uri_flag_is_valid;
    return uri;
}

uri uri::make_native_file_uri(std::string_view path)
{
#if defined(_WIN32)
    return make_file_uri(path, path_style::dos);
#else
    return make_file_uri(path, path_style::generic);
#endif
}

static std::string path_to_file_path(std::string_view uri_path, uri::path_style style)
{
    if (style == uri::path_style::dos)
    {
        bool has_slash_dos_drive =
            !uri_path.empty() && uri_path.front() == '/' &&
            path_has_dos_drive(uri_path.substr(1));
        std::string dos_path(
            uri_path.begin() + (has_slash_dos_drive ? 1 : 0), uri_path.end());
        for (char &c : dos_path) if (c == '/') c = '\\';
        return dos_path;
    }
    else
    {
        return std::string(uri_path);
    }
}

std::string uri::file_path(path_style style) const
{
    return path_to_file_path(m_priv->m_path, style);
}

std::string uri::native_file_path() const
{
#if defined(_WIN32)
    return file_path(path_style::dos);
#else
    return file_path(path_style::generic);
#endif
}

void uri::escape(std::string_view string, escape_mode mode, void *ctx, void (*write)(void *, const char *, size_t))
{
    {
        const char *cursor = string.data();
        const char *limit = cursor + string.size();

        for (;;)
        {
            const char *marker [[maybe_unused]];
            const char *p1, *p2;
            /*!stags:re2c:Escape format = 'const char *@@;\n'; */

            auto hex_encode = [](uint8_t byte, char hex[2])
            {
                const char digit[] = "0123456789abcdef";
                hex[0] = digit[byte >> 4];
                hex[1] = digit[byte & 15];
            };

/*!local:re2c:Escape
  !use:Common;

@p1 [0-9a-zA-Z\-_.~]* @p2
{
    write(ctx, p1, p2 - p1);
    goto next;
}

"/"
{
    if (mode == escape_mode::path)
    {
        write(ctx, "/", 1);
    }
    else
    {
        char hex[3];
        hex[0] = '%';
        hex_encode('/', hex + 1);
        write(ctx, hex, 3);
    }
    goto next;
}

" "
{
    char esc = (mode == escape_mode::query) ? '+' : ' ';
    write(ctx, &esc, 1);
    goto next;
}

@p1 [:@]
{
    if (mode == escape_mode::path || (mode == escape_mode::path_no_colon && *p1 != ':'))
    {
        write(ctx, p1, 1);
    }
    else
    {
        char hex[3];
        hex[0] = '%';
        hex_encode(*p1, hex + 1);
        write(ctx, hex, 3);
    }
    goto next;
}

@p1 any
{
    char hex[3];
    hex[0] = '%';
    hex_encode(*p1, hex + 1);
    write(ctx, hex, 3);
    goto next;
}

$
{
    return;
}

*/
        next: ;
        }
    }
}

bool uri::unescape(std::string_view string, escape_mode mode, void *ctx, void (*write)(void *, const char *, size_t))
{
    {
        const char *cursor = string.data();
        const char *limit = cursor + string.size();

        auto hex_digit = [](char c) -> unsigned int
        {
            if (c >= '0' && c <= '9') return (c - '0');
            if (c >= 'a' && c <= 'f') return (c - 'a') + 10;
            if (c >= 'A' && c <= 'F') return (c - 'A') + 10;
            return 0x100;
        };

        for (;;)
        {
            const char *marker [[maybe_unused]];
            const char *p1, *p2;
            /*!stags:re2c:Unescape format = 'const char *@@;\n'; */

/*!local:re2c:Unescape
  !use:Common;

"%" @p1 [a-fA-F0-9]{2} @p2
{
    char c = (char)((uint8_t)((hex_digit(p1[0]) << 4) | hex_digit(p1[1])));
    write(ctx, &c, 1);
    goto next;
}

"%"
{
    return false;
}

"+"
{
    char c = (mode == escape_mode::query) ? ' ' : '+';
    write(ctx, &c, 1);
    goto next;
}

@p1 [^%+]+ @p2
{
    write(ctx, p1, p2 - p1);
    goto next;
}

$
{
    return true;
}

*/
        next: ;
        }
    }
}

void uri::escape_to_string(std::string_view string, escape_mode mode, std::string *result)
{
    size_t count = 0;
    escape(string, mode, &count, [](void *ctx, const char *, size_t len)
    {
        *reinterpret_cast<size_t *>(ctx) += len;
    });

    result->reserve(result->size() + count);
    escape(string, mode, result, [](void *ctx, const char *str, size_t len)
    {
        reinterpret_cast<std::string *>(ctx)->append(str, len);
    });
}

bool uri::unescape_to_string(std::string_view string, escape_mode mode, std::string *result)
{
    size_t count = 0;
    bool success;

    success = unescape(string, mode, &count, [](void *ctx, const char *, size_t len)
    {
        *reinterpret_cast<size_t *>(ctx) += len;
    });
    if (!success)
        return false;

    result->reserve(result->size() + count);
    success = unescape(string, mode, result, [](void *ctx, const char *str, size_t len)
    {
        reinterpret_cast<std::string *>(ctx)->append(str, len);
    });
    return success;
}

bool uri::internal::parse_query(std::string_view string, std::vector<attribute> &qa)
{
    const char *cursor = string.data();
    const char *limit = cursor + string.size();

    for (;;)
    {
        const char *marker [[maybe_unused]];
        const char *k1, *k2, *v1, *v2;
        /*!stags:re2c:Query format = 'const char *@@;\n'; */

/*!local:re2c:Query
  !use:Common;

@k1 [^=&]* @k2 ("=" @v1 [^&]* @v2)? "&"?
{
    attribute a;
    if (!unescape_to_string(std::string_view(k1, k2 - k1), escape_mode::query, &a.key))
        return false;
    if (v1)
    {
        if (!unescape_to_string(std::string_view(v1, v2 - v1), escape_mode::query, &a.value))
            return false;
        a.has_value = true;
    }
    qa.push_back(std::move(a));
    goto next;
}

$
{
    return true;
}

*/
    next: ;
    }
}

void uri::format(void *ctx, void (*write)(void *, const char *, size_t)) const
{
    const internal *priv = m_priv.get();
    const int flags = priv ? priv->m_flags : 0;

    if (!(flags & uri_flag_is_valid))
        return;

    if (flags & uri_flag_has_scheme)
    {
        write(ctx, priv->m_scheme.data(), priv->m_scheme.size());
        write(ctx, ":", 1);
    }

    if (flags & uri_flag_has_authority)
    {
        write(ctx, "//", 2);
        if (flags & uri_flag_has_username)
        {
            uri::escape(priv->m_username, escape_mode::all, ctx, write);
            if (flags & uri_flag_has_password)
            {
                write(ctx, ":", 1);
                uri::escape(priv->m_password, escape_mode::all, ctx, write);
            }
            write(ctx, "@", 1);
        }
        uri::escape(priv->m_host, escape_mode::all, ctx, write);
        if (flags & uri_flag_has_port)
        {
            write(ctx, ":", 1);

            char port_buffer[8];
            char *port_string_end = &port_buffer[8];
            char *port_string = port_string_end;
            for (int x = priv->m_port; x > 0; x /= 10)
                *--port_string = '0' + (x % 10);
            if (*port_string == '\0')
                *--port_string = '0';

            write(ctx, port_string, port_string_end - port_string);
        }
    }

    {
        std::string_view path(priv->m_path);
        size_t pos = path.find('/');

        if (pos == path.npos)
        {
            uri::escape(path, escape_mode::path_no_colon, ctx, write);
        }
        else
        {
            uri::escape(path.substr(0, pos), escape_mode::path_no_colon, ctx, write);
            uri::escape(path.substr(pos), escape_mode::path, ctx, write);
        }
    }

    if (flags & uri_flag_has_query)
    {
        write(ctx, "?", 1);

        bool first = true;
        for (const attribute &qa : m_priv->m_query)
        {
            if (!first)
            {
                write(ctx, "&", 1);
            }
            uri::escape(qa.key, escape_mode::query, ctx, write);
            if (qa.has_value)
            {
                write(ctx, "=", 1);
                uri::escape(qa.value, escape_mode::query, ctx, write);
            }
            first = false;
        }
    }

    if (flags & uri_flag_has_fragment)
    {
        write(ctx, "#", 1);
        uri::escape(priv->m_fragment, escape_mode::all, ctx, write);
    }
}

std::string uri::to_string() const
{
    size_t count = 0;
    format(&count, [](void *ctx, const char *, size_t len)
    {
        *reinterpret_cast<size_t *>(ctx) += len;
    });

    std::string str;
    str.reserve(count);
    format(&str, [](void *ctx, const char *str, size_t len)
    {
        reinterpret_cast<std::string *>(ctx)->append(str, len);
    });

    return str;
}

template <typename T, class Hash = std::hash<T>>
static void hash_combine(size_t &seed, const T &val)
{
    seed ^= Hash{}(val) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

size_t uri::hash_code(size_t seed) const noexcept
{
    uint32_t tag =
        (uint32_t)'U' |
        ((uint32_t)'R' << 8) |
        ((uint32_t)'I' << 16) |
        ((uint32_t)' ' << 24);

    hash_combine(seed, tag);
    if (m_priv)
        seed = m_priv->hash_code(seed);
    return seed;
}

size_t uri::internal::hash_code(size_t seed) const noexcept
{
    hash_combine(seed, m_flags);

    if (m_flags & uri_flag_has_scheme)
        hash_combine(seed, m_scheme);

    if (m_flags & uri_flag_has_username)
        hash_combine(seed, m_username);

    if (m_flags & uri_flag_has_password)
        hash_combine(seed, m_password);

    if (m_flags & uri_flag_has_host)
        hash_combine(seed, m_host);

    if (m_flags & uri_flag_has_port)
        hash_combine(seed, m_port);

    hash_combine(seed, m_path);

    if (m_flags & uri_flag_has_query)
    {
        hash_combine(seed, m_query.size());

        for (const attribute &qa : m_query)
        {
            hash_combine(seed, qa.key);
            if (qa.has_value)
                hash_combine(seed, qa.value);
        }
    }

    if (m_flags & uri_flag_has_fragment)
        hash_combine(seed, m_fragment);

    return seed;
}

template <class T>
static int generic_compare(const T &a, const T &b)
{
    return (a == b) ? 0 : (a < b) ? -1 : +1;
}

static int string_compare(const std::string &a, const std::string &b)
{
    return strcmp(a.c_str(), b.c_str());
}

int uri::compare(const uri &other) const noexcept
{
    int order = generic_compare(bool(m_priv), bool(other.m_priv));
    if (order != 0)
        return order;

    return m_priv ? m_priv->compare(*other.m_priv) : 0;
}

int uri::internal::compare(const internal &other) const noexcept
{
    {
        int order = generic_compare(m_flags, other.m_flags);
        if (order != 0)
            return order;
    }

    if (m_flags & uri_flag_has_scheme)
    {
        int order = string_compare(m_scheme, other.m_scheme);
        if (order != 0)
            return order;
    }

    if (m_flags & uri_flag_has_username)
    {
        int order = string_compare(m_username, other.m_username);
        if (order != 0)
            return order;
    }

    if (m_flags & uri_flag_has_password)
    {
        int order = string_compare(m_password, other.m_password);
        if (order != 0)
            return order;
    }

    if (m_flags & uri_flag_has_host)
    {
        int order = string_compare(m_host, other.m_host);
        if (order != 0)
            return order;
    }

    if (m_flags & uri_flag_has_port)
    {
        int order = generic_compare(m_port, other.m_port);
        if (order != 0)
            return order;
    }

    {
        int order = string_compare(m_path, other.m_path);
        if (order != 0)
            return order;
    }

    if (m_flags & uri_flag_has_query)
    {
        int order = generic_compare(m_query.size(), other.m_query.size());
        if (order != 0)
            return order;

        for (size_t i = 0; i < m_query.size(); i++)
        {
            const attribute &a = m_query[i];
            const attribute &b = other.m_query[i];

            order = string_compare(a.key, b.key);
            if (order != 0)
                return order;

            order = generic_compare(a.has_value, b.has_value);
            if (order != 0)
                return order;

            order = string_compare(a.value, b.value);
            if (order != 0)
                return order;
        }
    }

    if (m_flags & uri_flag_has_fragment)
    {
        int order = string_compare(m_fragment, other.m_fragment);
        if (order != 0)
            return order;
    }

    return 0;
}

bool uri::operator==(const uri &other) const noexcept
{
    if (bool(m_priv) != bool(other.m_priv))
        return false;

    return m_priv ? (*m_priv == *other.m_priv) : true;
}

bool uri::internal::operator==(const internal &other) const noexcept
{
    if (m_flags != other.m_flags)
        return false;

    if (m_flags & uri_flag_has_scheme)
    {
        if (m_scheme != other.m_scheme)
            return false;
    }

    if (m_flags & uri_flag_has_username)
    {
        if (m_username != other.m_username)
            return false;
    }

    if (m_flags & uri_flag_has_password)
    {
        if (m_password != other.m_password)
            return false;
    }

    if (m_flags & uri_flag_has_host)
    {
        if (m_host != other.m_host)
            return false;
    }

    if (m_flags & uri_flag_has_port)
    {
        if (m_port != other.m_port)
            return false;
    }

    if (m_path != other.m_path)
        return false;

    if (m_flags & uri_flag_has_query)
    {
        if (m_query.size() != other.m_query.size())
            return false;

        for (size_t i = 0; i < m_query.size(); i++)
        {
            const attribute &a = m_query[i];
            const attribute &b = other.m_query[i];

            if (a.key != b.key)
                return false;

            if (a.has_value != b.has_value)
                return false;

            if (a.has_value && a.value != b.value)
                return false;
        }
    }

    if (m_flags & uri_flag_has_fragment)
    {
        if (m_fragment != other.m_fragment)
            return false;
    }

    return true;
}

void uri::internal_delete::operator()(internal *x) const noexcept
{
    delete x;
}

enum
{
    uri_builder_flag_has_scheme = (1 << 0),
    uri_builder_flag_prefer_authority = (1 << 1),
    uri_builder_flag_has_username = (1 << 2),
    uri_builder_flag_has_password = (1 << 3),
    uri_builder_flag_has_host = (1 << 4),
    uri_builder_flag_has_port = (1 << 5),
    uri_builder_flag_has_fragment = (1 << 6),
};

struct uri_builder::internal
{
    int m_flags = 0;
    std::string m_scheme;
    std::string m_username;
    std::string m_password;
    std::string m_host;
    int m_port = 0;
    std::string m_path;
    std::vector<uri::attribute> m_query;
    std::string m_fragment;
};

uri_builder::uri_builder()
    : m_priv(new internal)
{
}

void uri_builder::set_scheme(std::string scheme)
{
    m_priv->m_scheme = std::move(scheme);
    m_priv->m_flags |= uri_builder_flag_has_scheme;
}

void uri_builder::prefer_authority(bool prefer)
{
    if (prefer)
        m_priv->m_flags |= uri_builder_flag_prefer_authority;
    else
        m_priv->m_flags &= ~uri_builder_flag_prefer_authority;
}

void uri_builder::set_username(std::string username)
{
    m_priv->m_username = std::move(username);
    m_priv->m_flags |= uri_builder_flag_has_username;
}

void uri_builder::set_password(std::string password)
{
    m_priv->m_password = std::move(password);
    m_priv->m_flags |= uri_builder_flag_has_password;
}

void uri_builder::set_host(std::string host)
{
    m_priv->m_host = std::move(host);
    m_priv->m_flags |= uri_builder_flag_has_host;
}

void uri_builder::set_port(int port)
{
    m_priv->m_port = port;
    m_priv->m_flags |= uri_builder_flag_has_port;
}

void uri_builder::set_path(std::string path)
{
    m_priv->m_path = std::move(path);
}

void uri_builder::add_query_attribute(std::string key)
{
    uri::attribute qa;
    qa.key = std::move(key);
    m_priv->m_query.push_back(std::move(qa));
}

void uri_builder::add_query_attribute(std::string key, std::string value)
{
    uri::attribute qa;
    qa.key = std::move(key);
    qa.value = std::move(value);
    qa.has_value = true;
    m_priv->m_query.push_back(std::move(qa));
}

void uri_builder::set_fragment(std::string fragment)
{
    m_priv->m_fragment = std::move(fragment);
    m_priv->m_flags |= uri_builder_flag_has_fragment;
}

uri uri_builder::build()
{
    uri uri;
    uri.m_priv.reset(new uri::internal);

    auto validate_scheme = [](std::string_view scheme) -> bool
    {
        if (scheme.empty())
            return false;

        char c = scheme.front();
        bool valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        if (!valid)
            return false;

        for (size_t i = 1; i < scheme.size(); ++i)
        {
            c = scheme[i];
            valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || (c == '+') || (c == '.') || (c == '-');
            if (!valid)
                return false;
        }

        return true;
    };

    auto validate_host = [](std::string_view host) -> bool
    {
        if (host.empty())
            return false;

        if (host.front() == '[')
        {
            if (host.find(']') != host.size() - 1)
                return false;
        }
        else
        {
            if (host.find_first_of("/:") != host.npos)
                return false;
        }

        return true;
    };

    auto validate_port = [](int port) -> bool
    {
        return port >= 0 && port < 65536;
    };

    if (m_priv->m_flags & uri_builder_flag_has_scheme)
    {
        if (!validate_scheme(m_priv->m_scheme))
            return {};

        uri.m_priv->m_scheme = std::move(m_priv->m_scheme);
        uri.m_priv->m_flags |= uri::uri_flag_has_scheme;
    }

    if (m_priv->m_flags & uri_builder_flag_has_username)
    {
        uri.m_priv->m_username = std::move(m_priv->m_username);
        uri.m_priv->m_flags |= uri::uri_flag_has_username;
    }

    if (m_priv->m_flags & uri_builder_flag_has_password)
    {
        uri.m_priv->m_password = std::move(m_priv->m_password);
        uri.m_priv->m_flags |= uri::uri_flag_has_password;
    }

    if (m_priv->m_flags & uri_builder_flag_has_host)
    {
        if (!validate_host(m_priv->m_host))
            return {};

        uri.m_priv->m_host = std::move(m_priv->m_host);
        uri.m_priv->m_flags |= uri::uri_flag_has_host|uri::uri_flag_has_authority;
    }

    if (m_priv->m_flags & uri_builder_flag_has_port)
    {
        if (!validate_port(m_priv->m_port))
            return {};

        uri.m_priv->m_port = m_priv->m_port;
        uri.m_priv->m_flags |= uri::uri_flag_has_port;
    }

    if (path_is_authority_compatible(m_priv->m_path))
    {
        if ((m_priv->m_flags & uri_builder_flag_prefer_authority) ||
            path_is_authority_required(m_priv->m_path))
        {
            uri.m_priv->m_flags |= uri::uri_flag_has_authority;
        }
    }
    else if (uri.m_priv->m_flags & uri::uri_flag_has_authority)
    {
        return {};
    }

    uri.m_priv->m_path = std::move(m_priv->m_path);

    if (!m_priv->m_query.empty())
    {
        uri.m_priv->m_query = std::move(m_priv->m_query);
        uri.m_priv->m_flags |= uri::uri_flag_has_query;
    }

    if (m_priv->m_flags & uri_builder_flag_has_fragment)
    {
        uri.m_priv->m_fragment = std::move(m_priv->m_fragment);
        uri.m_priv->m_flags |= uri::uri_flag_has_fragment;
    }

    uri.m_priv->m_flags |= uri::uri_flag_is_valid;
    return uri;
}

void uri_builder::internal_delete::operator()(internal *x) const noexcept
{
    delete x;
}

}
// namespace sel
