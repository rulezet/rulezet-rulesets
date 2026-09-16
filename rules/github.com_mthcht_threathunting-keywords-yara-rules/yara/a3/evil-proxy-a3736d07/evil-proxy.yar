rule evil_proxy
{
    meta:
        description = "Detection patterns for the tool 'evil-proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evil-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " evil-proxy" nocase ascii wide
                        $string2 = /\sevil\-proxy\.rb/ nocase ascii wide
                        $string3 = " install evil-proxy" nocase ascii wide
                        $string4 = /\.\/evil\-proxy/
                        $string5 = /\/evil\-proxy\.git/ nocase ascii wide
                        $string6 = /\/evil\-proxy\.rb/ nocase ascii wide
                        $string7 = "/evil-proxy/"
                        $string8 = "@mitm_pattern = " nocase ascii wide
                        $string9 = "@mitm_port = " nocase ascii wide
                        $string10 = "@mitm_servers =" nocase ascii wide
                        $string11 = /\\evil\-proxy\.rb/ nocase ascii wide
                        $string12 = /\\evil\-proxy\\/ nocase ascii wide
                        $string13 = "= \"evil-proxy\"" nocase ascii wide
                        $string14 = /127\.0\.0\.1\:\#\{mitm_port\}/ nocase ascii wide
                        $string15 = /A\sruby\shttp\/https\sproxy\sto\sdo\sEVIL\sthings\./ nocase ascii wide
                        $string16 = "bbtfr/evil-proxy" nocase ascii wide
                        $string17 = /evil\-proxy\.gemspec/ nocase ascii wide
                        $string18 = "evil-proxy/agentproxy" nocase ascii wide
                        $string19 = "evil-proxy/httpproxy" nocase ascii wide
                        $string20 = "evil-proxy/selenium" nocase ascii wide
                        $string21 = "evil-proxy/version" nocase ascii wide
                        $string22 = "EvilProxy::HTTPProxyServer" nocase ascii wide
                        $string23 = "EvilProxy::MITMProxyServer" nocase ascii wide
                        $string24 = /evil\-proxy\-0\.1\.0/ nocase ascii wide
                        $string25 = /evil\-proxy\-0\.2\.0/ nocase ascii wide
                        $string26 = "evil-proxy-master" nocase ascii wide
                        $string27 = "gem 'evil-proxy'" nocase ascii wide
                        $string28 = /http\:\/\/101\.251\.217\.210/ nocase ascii wide
                        $string29 = /HTTPClient\.post\(\'https\:\/\/httpbin\.org\/post/ nocase ascii wide
                        $string30 = /mitmproxy\.rb/ nocase ascii wide
                        $string31 = "module EvilProxy" nocase ascii wide
                        $string32 = "require 'evil-proxy'" nocase ascii wide
                        $string33 = "require 'evil-proxy/async'" nocase ascii wide
                        $string34 = "require 'evil-proxy/store'" nocase ascii wide
                        $string35 = "vil-proxy/quickcert" nocase ascii wide
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