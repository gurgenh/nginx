# Copyright (C) 2015-2016 Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

_common_copts = [
    "-fno-common",
    "-fvisibility=hidden",
    "-Wall",
    "-Werror",
    "-Wextra",
    "-Wformat=2",
    "-Wlong-long",
    "-Wpointer-arith",
    "-Wshadow",
    "-Wno-unused-parameter",
]

nginx_copts = _common_copts + [
    "-Wmissing-prototypes",
    "-Wold-style-definition",
    "-Wstrict-prototypes",
]

nginx_cxxopts = _common_copts + [
    "-Wmissing-declarations",
]

_PCRE_BUILD_FILE = """
# Copyright (C) 2015-2016 Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

licenses(["notice"])

exports_files(["LICENCE"])

genrule(
    name = "config_h",
    srcs = [
        "config.h.generic",
    ],
    outs = [
        "config.h",
    ],
    cmd = "cp -p $(<) $(@)",
)

genrule(
    name = "pcre_h",
    srcs = [
        "pcre.h.generic",
    ],
    outs = [
        "pcre.h",
    ],
    cmd = "cp -p $(<) $(@)",
)

genrule(
    name = "pcre_chartables_c",
    srcs = [
        "pcre_chartables.c.dist",
    ],
    outs = [
        "pcre_chartables.c",
    ],
    cmd = "cp -p $(<) $(@)",
)

cc_library(
    name = "sljit",
    srcs = [
        "sljit/sljitConfig.h",
        "sljit/sljitConfigInternal.h",
        "sljit/sljitLir.h",
    ],
    hdrs = [
        "sljit/sljitExecAllocator.c",
        "sljit/sljitLir.c",
        "sljit/sljitNativeX86_64.c",
        "sljit/sljitNativeX86_common.c",
        "sljit/sljitUtils.c",
    ],
)

cc_library(
    name = "pcre",
    srcs = [
        "config.h",
        "pcre_byte_order.c",
        "pcre_chartables.c",
        "pcre_compile.c",
        "pcre_config.c",
        "pcre_dfa_exec.c",
        "pcre_exec.c",
        "pcre_fullinfo.c",
        "pcre_get.c",
        "pcre_globals.c",
        "pcre_internal.h",
        "pcre_jit_compile.c",
        "pcre_maketables.c",
        "pcre_newline.c",
        "pcre_ord2utf8.c",
        "pcre_refcount.c",
        "pcre_study.c",
        "pcre_tables.c",
        "pcre_ucd.c",
        "pcre_valid_utf8.c",
        "pcre_version.c",
        "pcre_xclass.c",
        "ucp.h",
    ],
    hdrs = [
        "pcre.h",
    ],
    copts = [
        "-DHAVE_CONFIG_H",
        "-DHAVE_MEMMOVE",
        "-DHAVE_STDINT_H",
        "-DNO_RECURSE",
        "-DSUPPORT_JIT",
        "-DSUPPORT_PCRE8",
        "-DSUPPORT_UCP",
        "-DSUPPORT_UTF",
    ],
    includes = [
        ".",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":sljit",
    ],
)
"""

_PKGOSS_BUILD_FILE = """
# Copyright (C) 2015-2016 Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

licenses(["notice"])

exports_files(["README"])

load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")

genrule(
    name = "debian_nginx_preinst",
    srcs = [
        "debian/nginx.preinst",
    ],
    outs = [
        "nginx.preinst",
    ],
    cmd = "sed -e 's|#DEBHELPER#||g'" +
          " < $(<) > $(@)",
)

filegroup(
    name = "debian_preinst",
    srcs = [
        "nginx.preinst",
    ],
    visibility = [
        "//visibility:public",
    ],
)

filegroup(
    name = "debian_postinst",
    srcs = [
        "debian/nginx.postinst",
    ],
    visibility = [
        "//visibility:public",
    ],
)

filegroup(
    name = "debian_prerm",
    srcs = [
        "debian/nginx.prerm",
    ],
    visibility = [
        "//visibility:public",
    ],
)

genrule(
    name = "debian_nginx_postrm",
    srcs = [
        "debian/nginx.postrm",
    ],
    outs = [
        "nginx.postrm",
    ],
    cmd = "sed -e 's|#DEBHELPER#|" +
          "if [ \\"$$1\\" = \\"purge\\" ] ; then\\\\n" +
          "    update-rc.d nginx remove >/dev/null\\\\n" +
          "fi\\\\n" +
          "\\\\n" +
          "if [ -d /run/systemd/system ] ; then\\\\n" +
          "    systemctl --system daemon-reload >/dev/null \\|\\| true\\\\n" +
          "fi\\\\n" +
          "|g'" +
          " < $(<) > $(@)",
)

filegroup(
    name = "debian_postrm",
    srcs = [
        "nginx.postrm",
    ],
    visibility = [
        "//visibility:public",
    ],
)

genrule(
    name = "debian_etc_default_nginx",
    srcs = [
        "debian/nginx.default",
    ],
    outs = [
        "etc/default/nginx",
    ],
    cmd = "cp -p $(<) $(@)",
)

genrule(
    name = "debian_etc_init_d_nginx",
    srcs = [
        "debian/init.d.in",
    ],
    outs = [
        "etc/init.d/nginx",
    ],
    cmd = "sed -e 's|%%PROVIDES%%|nginx|g'" +
          " -e 's|%%DEFAULTSTART%%|2 3 4 5|g'" +
          " -e 's|%%DEFAULTSTOP%%|0 1 6|g'" +
          " < $(<) > $(@)",
)

genrule(
    name = "debian_etc_logrotate_d_nginx",
    srcs = [
        "debian/logrotate",
    ],
    outs = [
        "etc/logrotate.d/nginx",
    ],
    cmd = "cp -p $(<) $(@)",
)

genrule(
    name = "debian_etc_nginx_conf_d_default_conf",
    srcs = [
        "debian/nginx.vh.default.conf",
    ],
    outs = [
        "etc/nginx/conf.d/default.conf",
    ],
    cmd = "cp -p $(<) $(@)",
)

genrule(
    name = "debian_etc_nginx_nginx_conf",
    srcs = [
        "debian/nginx.conf",
    ],
    outs = [
        "etc/nginx/nginx.conf",
    ],
    cmd = "cp -p $(<) $(@)",
)

genrule(
    name = "debian_var_cache_nginx",
    outs = [
        "var/cache/nginx/.empty",
    ],
    cmd = "touch $(@)",
)

genrule(
    name = "debian_var_log_nginx",
    outs = [
        "var/log/nginx/.empty",
    ],
    cmd = "touch $(@)",
)

pkg_tar(
    name = "debian_etc_nginx",
    files = [
        "{nginx}:config_includes",
    ],
    mode = "0644",
    package_dir = "/etc/nginx",
)

pkg_tar(
    name = "debian_usr_share_nginx_html",
    files = [
        "{nginx}:html_files",
    ],
    mode = "0644",
    package_dir = "/usr/share/nginx/html",
)

pkg_tar(
    name = "debian_var",
    files = [
        "var/cache/nginx/.empty",
        "var/log/nginx/.empty",
    ],
    mode = "0644",
    strip_prefix = ".",
)
"""

_PKGOSS_BUILD_FILE_TAIL = """
pkg_tar(
    name = "debian_overlay",
    files = [
        "etc/default/nginx",
        "etc/init.d/nginx",
        "etc/logrotate.d/nginx",
        "etc/nginx/conf.d/default.conf",
        "etc/nginx/nginx.conf",
    ],
    mode = "0644",
    modes = {
        "etc/init.d/nginx": "0755",
    },
    strip_prefix = ".",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        ":debian_etc_nginx",
        ":debian_usr_share_nginx_html",
        ":debian_var",
    ],
)
"""

_ZLIB_BUILD_FILE = """
# Copyright (C) 2015-2016 Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

licenses(["notice"])

exports_files(["README"])

cc_library(
    name = "zlib",
    srcs = [
        "adler32.c",
        "crc32.c",
        "crc32.h",
        "deflate.c",
        "deflate.h",
        "infback.c",
        "inffast.c",
        "inffast.h",
        "inffixed.h",
        "inflate.c",
        "inflate.h",
        "inftrees.c",
        "inftrees.h",
        "trees.c",
        "trees.h",
        "zconf.h",
        "zutil.c",
        "zutil.h",
    ],
    hdrs = [
        "zlib.h",
    ],
    copts = [
        "-Wno-shift-negative-value",
        "-Wno-unknown-warning-option",
    ],
    defines = [
        "Z_SOLO",
    ],
    visibility = [
        "//visibility:public",
    ],
)
"""

def nginx_repositories_boringssl(bind):
    native.git_repository(
        name = "boringssl",
        commit = "2f29d38cc5e6c1bfae4ce22b4b032fb899cdb705",  # 2016-07-12
        remote = "https://boringssl.googlesource.com/boringssl",
    )

    if bind:
        native.bind(
            name = "boringssl_crypto",
            actual = "@boringssl//:crypto"
        )

        native.bind(
            name = "boringssl_ssl",
            actual = "@boringssl//:ssl"
        )

def nginx_repositories_pcre(bind):
    native.new_http_archive(
        name = "nginx_pcre",
        build_file_content = _PCRE_BUILD_FILE,
        sha256 = "ccdf7e788769838f8285b3ee672ed573358202305ee361cfec7a4a4fb005bbc7",
        strip_prefix = "pcre-8.39",
        url = "http://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.39.tar.gz",
    )

    if bind:
        native.bind(
            name = "pcre",
            actual = "@nginx_pcre//:pcre"
        )

def nginx_repositories_pkgoss(nginx):
    native.new_git_repository(
        name = "nginx_pkgoss",
        build_file_content = _PKGOSS_BUILD_FILE.format(nginx = nginx) +
                             _PKGOSS_BUILD_FILE_TAIL,
        commit = "a2ada68a6f263472a52a2cba1b0629eacbf05953",  # nginx-1.11.3
        remote = "https://nginx.googlesource.com/nginx-pkgoss",
    )

def nginx_repositories_zlib(bind):
    native.new_git_repository(
        name = "nginx_zlib",
        build_file_content = _ZLIB_BUILD_FILE,
        commit = "50893291621658f355bc5b4d450a8d06a563053d",  # v1.2.8
        remote = "https://github.com/madler/zlib.git",
    )

    if bind:
        native.bind(
            name = "zlib",
            actual = "@nginx_zlib//:zlib"
        )

def nginx_repositories(bind = False, nginx = "@nginx//"):
    # core dependencies
    nginx_repositories_boringssl(bind)
    nginx_repositories_pcre(bind)
    nginx_repositories_zlib(bind)

    # packaging
    nginx_repositories_pkgoss(nginx)
