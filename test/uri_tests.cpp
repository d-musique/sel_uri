// The SEL extension library
// Free software published under the MIT license.

#include "sel/uri.hpp"
#include <doctest/doctest.h>
#include <vector>
#include <stdint.h>

struct test_t
{
    std::string_view string;
    std::string_view scheme;
    std::string_view username;
    std::string_view password;
    std::string_view host;
    int port = -1;
    std::string_view path;
    std::vector<std::pair<std::string_view, std::string_view>> query;
    std::string_view fragment;
    int flags = 0;
};

enum flag_t
{
    is_invalid = (1 << 0),
    prefer_authority = (1 << 1),
};

static const test_t all_tests[] =
{
    {.string="path",
     .path="path"},
    {.string="scheme:path",
     .scheme="scheme", .path="path"},
    {.string="scheme:path#",
     .scheme="scheme", .path="path", .fragment=""},
    {.string="scheme:path?attr1=value1&attr2#frag",
     .scheme="scheme", .path="path", .query={{"attr1", "value1"}, {"attr2", {}}}, .fragment="frag"},
    {.string="scheme:/path",
     .scheme="scheme", .path="/path"},
    // authority
    {.string="scheme:///path",
     .scheme="scheme", .path="/path", .flags=prefer_authority},
    {.string="scheme://user@host/path",
     .scheme="scheme", .username="user", .host="host", .path="/path"},
    {.string="scheme://user@host:100/path",
     .scheme="scheme", .username="user", .host="host", .port=100, .path="/path"},
    // file
    {.string="file:///C:/file.txt",
     .scheme="file", .path="/C:/file.txt", .flags=prefer_authority},
    {.string="file:///etc/file.txt",
     .scheme="file", .path="/etc/file.txt", .flags=prefer_authority},
    // invalid scheme
    {.string="",
     .scheme="invalid:scheme", .flags=is_invalid},
    // invalid port
    {.string="scheme://user@host:1000000/path",
     .port=1000000, .flags=is_invalid},
    // escaped path
    {.string="scheme:pa%3fth",
     .scheme="scheme", .path="pa?th"},
    // escaped authority
    {.string="scheme://u%40s%3ae%2fr@host/path",
     .scheme="scheme", .username="u@s:e/r", .host="host", .path="/path"},
    // escaped query
    {.string="scheme:path?at%3dtr1=va%3dlue1",
     .scheme="scheme", .path="path", .query{{"at=tr1", "va=lue1"}}},
    {.string="scheme:path?at%23tr1=va%23lue1",
     .scheme="scheme", .path="path", .query{{"at#tr1", "va#lue1"}}},
    {.string="scheme:path?at+tr1=va+lue1",
     .scheme="scheme", .path="path", .query{{"at tr1", "va lue1"}}},
};

TEST_CASE("URI: general")
{
    for (const test_t &test : all_tests)
    {
        sel::uri built_uri;
        {
            sel::uri_builder ub;
            if (test.scheme.data())
                ub.set_scheme(std::string(test.scheme));
            if (test.username.data())
                ub.set_username(std::string(test.username));
            if (test.password.data())
                ub.set_password(std::string(test.password));
            if (test.host.data())
                ub.set_host(std::string(test.host));
            if (test.port != -1)
                ub.set_port(test.port);
            ub.set_path(std::string(test.path));
            for (const std::pair<std::string_view, std::string_view> attr : test.query)
            {
                if (attr.second.data())
                    ub.add_query_attribute(std::string(attr.first), std::string(attr.second));
                else
                    ub.add_query_attribute(std::string(attr.first));
            }
            if (test.fragment.data())
                ub.set_fragment(std::string(test.fragment));
            ub.prefer_authority(test.flags & prefer_authority);
            built_uri = ub.build();
        }

        sel::uri parsed_uri = sel::uri::parse(test.string);

        if (test.flags & is_invalid)
        {
            REQUIRE(!built_uri.valid());
            REQUIRE(!parsed_uri.valid());
            continue;
        }

        if (1)
        {
            REQUIRE(parsed_uri == built_uri);
            REQUIRE(parsed_uri.to_string() == test.string);
        }

        REQUIRE(parsed_uri.has_scheme() == (test.scheme.data() != nullptr));
        //REQUIRE(parsed_uri.has_authority() == );
        REQUIRE(parsed_uri.has_username() == (test.username.data() != nullptr));
        REQUIRE(parsed_uri.has_password() == (test.password.data() != nullptr));
        REQUIRE(parsed_uri.has_host() == (test.host.data() != nullptr));
        REQUIRE(parsed_uri.has_port() == (test.port >= 0));
        REQUIRE(parsed_uri.has_query() == (test.query.data() != nullptr));
        REQUIRE(parsed_uri.has_fragment() == (test.fragment.data() != nullptr));

        REQUIRE(parsed_uri.scheme() == test.scheme);
        REQUIRE(parsed_uri.username() == test.username);
        REQUIRE(parsed_uri.password() == test.password);
        REQUIRE(parsed_uri.host() == test.host);
        if (test.port != -1) REQUIRE(parsed_uri.port() == test.port);
        REQUIRE(parsed_uri.path() == test.path);
        REQUIRE(parsed_uri.query().size() == test.query.size());
        for (size_t i = 0; i < test.query.size(); ++i)
        {
            const sel::uri::attribute &qa = parsed_uri.query()[i];;
            REQUIRE(qa.has_value == (test.query[i].second.data() != nullptr));
            REQUIRE(qa.key == test.query[i].first);
            REQUIRE(qa.value == test.query[i].second);
        }
        REQUIRE(parsed_uri.fragment() == test.fragment);
    }
}

struct file_test_t
{
    std::string_view string;
    sel::uri::path_style style;
    std::string_view path;
    std::string_view native;
};

static const file_test_t all_file_tests[] =
{
    // dos
    {.string="file:///C:/dir/file.ext",
     .style=sel::uri::path_style::dos, .path="C:/dir/file.ext", .native="C:\\dir\\file.ext"},
    {.string="file:dir/file.ext",
     .style=sel::uri::path_style::dos, .path="dir/file.ext", .native="dir\\file.ext"},
    // generic
    {.string="file:///dir/file.ext",
     .style=sel::uri::path_style::generic, .path="/dir/file.ext"},
    {.string="file:dir/file.ext",
     .style=sel::uri::path_style::generic, .path="dir/file.ext"},
};

TEST_CASE("URI: file")
{
    for (const file_test_t &test : all_file_tests)
    {
        sel::uri built_uri = sel::uri::make_file_uri(test.path, test.style);
        sel::uri parsed_uri = sel::uri::parse(test.string);

        REQUIRE(built_uri.valid());
        REQUIRE(parsed_uri.valid());

        if (1)
        {
            REQUIRE(parsed_uri == built_uri);
            REQUIRE(parsed_uri.to_string() == test.string);
        }

        if (test.native.data() == nullptr)
        {
            REQUIRE(built_uri.file_path(test.style) == test.path);
        }
        else
        {
            sel::uri built2_uri = sel::uri::make_file_uri(test.native, test.style);
            REQUIRE(built_uri.file_path(test.style) == test.native);
            REQUIRE(built2_uri.file_path(test.style) == test.native);
        }
    }
}
