rule rule_evil_proxy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'evil-proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_evil_proxy_offensive_tool_keyword = " evil-proxy" nocase ascii wide
                        $string2_evil_proxy_offensive_tool_keyword = /\sevil\-proxy\.rb/ nocase ascii wide
                        $string3_evil_proxy_offensive_tool_keyword = " install evil-proxy" nocase ascii wide
                        $string4_evil_proxy_offensive_tool_keyword = /\.\/evil\-proxy/
                        $string5_evil_proxy_offensive_tool_keyword = /\/evil\-proxy\.git/ nocase ascii wide
                        $string6_evil_proxy_offensive_tool_keyword = /\/evil\-proxy\.rb/ nocase ascii wide
                        $string7_evil_proxy_offensive_tool_keyword = "/evil-proxy/"
                        $string8_evil_proxy_offensive_tool_keyword = "@mitm_pattern = " nocase ascii wide
                        $string9_evil_proxy_offensive_tool_keyword = "@mitm_port = " nocase ascii wide
                        $string10_evil_proxy_offensive_tool_keyword = "@mitm_servers =" nocase ascii wide
                        $string11_evil_proxy_offensive_tool_keyword = /\\evil\-proxy\.rb/ nocase ascii wide
                        $string12_evil_proxy_offensive_tool_keyword = /\\evil\-proxy\\/ nocase ascii wide
                        $string13_evil_proxy_offensive_tool_keyword = "= \"evil-proxy\"" nocase ascii wide
                        $string14_evil_proxy_offensive_tool_keyword = /127\.0\.0\.1\:\#\{mitm_port\}/ nocase ascii wide
                        $string15_evil_proxy_offensive_tool_keyword = /A\sruby\shttp\/https\sproxy\sto\sdo\sEVIL\sthings\./ nocase ascii wide
                        $string16_evil_proxy_offensive_tool_keyword = "bbtfr/evil-proxy" nocase ascii wide
                        $string17_evil_proxy_offensive_tool_keyword = /evil\-proxy\.gemspec/ nocase ascii wide
                        $string18_evil_proxy_offensive_tool_keyword = "evil-proxy/agentproxy" nocase ascii wide
                        $string19_evil_proxy_offensive_tool_keyword = "evil-proxy/httpproxy" nocase ascii wide
                        $string20_evil_proxy_offensive_tool_keyword = "evil-proxy/selenium" nocase ascii wide
                        $string21_evil_proxy_offensive_tool_keyword = "evil-proxy/version" nocase ascii wide
                        $string22_evil_proxy_offensive_tool_keyword = "EvilProxy::HTTPProxyServer" nocase ascii wide
                        $string23_evil_proxy_offensive_tool_keyword = "EvilProxy::MITMProxyServer" nocase ascii wide
                        $string24_evil_proxy_offensive_tool_keyword = /evil\-proxy\-0\.1\.0/ nocase ascii wide
                        $string25_evil_proxy_offensive_tool_keyword = /evil\-proxy\-0\.2\.0/ nocase ascii wide
                        $string26_evil_proxy_offensive_tool_keyword = "evil-proxy-master" nocase ascii wide
                        $string27_evil_proxy_offensive_tool_keyword = "gem 'evil-proxy'" nocase ascii wide
                        $string28_evil_proxy_offensive_tool_keyword = /http\:\/\/101\.251\.217\.210/ nocase ascii wide
                        $string29_evil_proxy_offensive_tool_keyword = /HTTPClient\.post\(\'https\:\/\/httpbin\.org\/post/ nocase ascii wide
                        $string30_evil_proxy_offensive_tool_keyword = /mitmproxy\.rb/ nocase ascii wide
                        $string31_evil_proxy_offensive_tool_keyword = "module EvilProxy" nocase ascii wide
                        $string32_evil_proxy_offensive_tool_keyword = "require 'evil-proxy'" nocase ascii wide
                        $string33_evil_proxy_offensive_tool_keyword = "require 'evil-proxy/async'" nocase ascii wide
                        $string34_evil_proxy_offensive_tool_keyword = "require 'evil-proxy/store'" nocase ascii wide
                        $string35_evil_proxy_offensive_tool_keyword = "vil-proxy/quickcert" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}