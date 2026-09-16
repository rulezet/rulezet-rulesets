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

    condition:
        any of them
}