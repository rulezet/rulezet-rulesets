rule rule_burpsuite_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'burpsuite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "burpsuite"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_burpsuite_offensive_tool_keyword = /\sDigitalOceanProxyTab\.java/ nocase ascii wide
                        $string2_burpsuite_offensive_tool_keyword = "/awesome-burp-extensions/" nocase ascii wide
                        $string3_burpsuite_offensive_tool_keyword = "/burp/releases/community/latest" nocase ascii wide
                        $string4_burpsuite_offensive_tool_keyword = "/burp-api/" nocase ascii wide
                        $string5_burpsuite_offensive_tool_keyword = /\/BurpExtender\.java/ nocase ascii wide
                        $string6_burpsuite_offensive_tool_keyword = "/BurpSuite-collections" nocase ascii wide
                        $string7_burpsuite_offensive_tool_keyword = "/co2-cewler/" nocase ascii wide
                        $string8_burpsuite_offensive_tool_keyword = "/co2-core/" nocase ascii wide
                        $string9_burpsuite_offensive_tool_keyword = "/co2-laudanum/" nocase ascii wide
                        $string10_burpsuite_offensive_tool_keyword = "/co2-sqlmapper/" nocase ascii wide
                        $string11_burpsuite_offensive_tool_keyword = /\/DigitalOceanProxyTab\.java/ nocase ascii wide
                        $string12_burpsuite_offensive_tool_keyword = "/http-request-smuggler/" nocase ascii wide
                        $string13_burpsuite_offensive_tool_keyword = "/laconicwolf/burp-extensions" nocase ascii wide
                        $string14_burpsuite_offensive_tool_keyword = /\/turbo\-intruder\-all\.jar/ nocase ascii wide
                        $string15_burpsuite_offensive_tool_keyword = /\\DigitalOceanProxyTab\.java/ nocase ascii wide
                        $string16_burpsuite_offensive_tool_keyword = /\\http\-request\-smuggler\\/ nocase ascii wide
                        $string17_burpsuite_offensive_tool_keyword = /\\turbo\-intruder\-all\.jar/ nocase ascii wide
                        $string18_burpsuite_offensive_tool_keyword = "4955d7e8fc3d3ded8e3b95757c78b3c4cd969b5fbb92a65267e6141b8faa83d5" nocase ascii wide
                        $string19_burpsuite_offensive_tool_keyword = "Burp Suite" nocase ascii wide
                        $string20_burpsuite_offensive_tool_keyword = /burp.{0,1000}PayloadParser\.py/ nocase ascii wide
                        $string21_burpsuite_offensive_tool_keyword = /burp.{0,1000}SQLMapper\.xml/ nocase ascii wide
                        $string22_burpsuite_offensive_tool_keyword = /burp\.extension\-payloadparser/ nocase ascii wide
                        $string23_burpsuite_offensive_tool_keyword = /Burp_start\.bat/ nocase ascii wide
                        $string24_burpsuite_offensive_tool_keyword = /Burp_start_en\.bat/ nocase ascii wide
                        $string25_burpsuite_offensive_tool_keyword = "burp-co2/out/artifacts" nocase ascii wide
                        $string26_burpsuite_offensive_tool_keyword = /BurpCO2Suite\.xml/ nocase ascii wide
                        $string27_burpsuite_offensive_tool_keyword = /burpcollaborator\.net/ nocase ascii wide
                        $string28_burpsuite_offensive_tool_keyword = /BurpFunctions\.java/ nocase ascii wide
                        $string29_burpsuite_offensive_tool_keyword = /BurpShiroPassiveScan\.jar/ nocase ascii wide
                        $string30_burpsuite_offensive_tool_keyword = "Burpsuite" nocase ascii wide
                        $string31_burpsuite_offensive_tool_keyword = /burpsuite.{0,1000}\.exe/ nocase ascii wide
                        $string32_burpsuite_offensive_tool_keyword = /burpsuite.{0,1000}\.jar/ nocase ascii wide
                        $string33_burpsuite_offensive_tool_keyword = /burpsuite.{0,1000}\.sh/ nocase ascii wide
                        $string34_burpsuite_offensive_tool_keyword = /burpsuite.{0,1000}\.zip/ nocase ascii wide
                        $string35_burpsuite_offensive_tool_keyword = /BurpSuiteCn\.jar/ nocase ascii wide
                        $string36_burpsuite_offensive_tool_keyword = "BurpSuiteHTTPSmuggler" nocase ascii wide
                        $string37_burpsuite_offensive_tool_keyword = /burp\-vulners\-scanner\-.{0,1000}\.jar/ nocase ascii wide
                        $string38_burpsuite_offensive_tool_keyword = "burp-xss-sql-plugin" nocase ascii wide
                        $string39_burpsuite_offensive_tool_keyword = /bypasswaf\.jar/ nocase ascii wide
                        $string40_burpsuite_offensive_tool_keyword = /captcha\-killer\..{0,1000}\.jar/ nocase ascii wide
                        $string41_burpsuite_offensive_tool_keyword = "CN=PortSwigger" nocase ascii wide
                        $string42_burpsuite_offensive_tool_keyword = "Creating DigitalOcean OVPN Proxy tab" nocase ascii wide
                        $string43_burpsuite_offensive_tool_keyword = "Destroying all droplets" nocase ascii wide
                        $string44_burpsuite_offensive_tool_keyword = /digitalocean\-droplet\-openvpn\-all\.jar/ nocase ascii wide
                        $string45_burpsuite_offensive_tool_keyword = /DigitalOceanProxyTab\$1\.class/ nocase ascii wide
                        $string46_burpsuite_offensive_tool_keyword = /domain_hunter\-v.{0,1000}\.jar/ nocase ascii wide
                        $string47_burpsuite_offensive_tool_keyword = /FastjsonScan\.jar/ nocase ascii wide
                        $string48_burpsuite_offensive_tool_keyword = "Generated random password for socks proxy:" nocase ascii wide
                        $string49_burpsuite_offensive_tool_keyword = /GenerateForcedBrowseWordlist\.py/ nocase ascii wide
                        $string50_burpsuite_offensive_tool_keyword = /GenerateParameterWordlist\.py/ nocase ascii wide
                        $string51_burpsuite_offensive_tool_keyword = /http\:\/\/.{0,1000}\.oast\.fun\// nocase ascii wide
                        $string52_burpsuite_offensive_tool_keyword = /http\:\/\/.{0,1000}\.oast\.live\// nocase ascii wide
                        $string53_burpsuite_offensive_tool_keyword = /http\:\/\/.{0,1000}\.oast\.me\// nocase ascii wide
                        $string54_burpsuite_offensive_tool_keyword = /http\:\/\/.{0,1000}\.oast\.online\// nocase ascii wide
                        $string55_burpsuite_offensive_tool_keyword = /http\:\/\/.{0,1000}\.oast\.pro\// nocase ascii wide
                        $string56_burpsuite_offensive_tool_keyword = /http\:\/\/.{0,1000}\.oast\.site\// nocase ascii wide
                        $string57_burpsuite_offensive_tool_keyword = /http\:\/\/.{0,1000}\.oastify\.com\// nocase ascii wide
                        $string58_burpsuite_offensive_tool_keyword = /http\-request\-smuggler\-all\.jar/ nocase ascii wide
                        $string59_burpsuite_offensive_tool_keyword = /httpsmuggler\.jar/ nocase ascii wide
                        $string60_burpsuite_offensive_tool_keyword = /IBurpExtender\.java/ nocase ascii wide
                        $string61_burpsuite_offensive_tool_keyword = /IBurpExtenderCallbacks\.java/ nocase ascii wide
                        $string62_burpsuite_offensive_tool_keyword = /InjectMate\.py/ nocase ascii wide
                        $string63_burpsuite_offensive_tool_keyword = /InjectMateCommunity\.py/ nocase ascii wide
                        $string64_burpsuite_offensive_tool_keyword = /IntruderPayloadGeneratorFactory\.class/ nocase ascii wide
                        $string65_burpsuite_offensive_tool_keyword = /IntruderPayloadProcessor\.class/ nocase ascii wide
                        $string66_burpsuite_offensive_tool_keyword = "JGillam/burp-co2" nocase ascii wide
                        $string67_burpsuite_offensive_tool_keyword = /LFI\sscanner\schecks\.jar/ nocase ascii wide
                        $string68_burpsuite_offensive_tool_keyword = /MakeHTTPSmugglerJAR\.launch/ nocase ascii wide
                        $string69_burpsuite_offensive_tool_keyword = /OpenVPN\/SOCKS\sextension\sinitialized\./ nocase ascii wide
                        $string70_burpsuite_offensive_tool_keyword = /perfdata\.portswigger\.net/ nocase ascii wide
                        $string71_burpsuite_offensive_tool_keyword = /portswigger\.net/ nocase ascii wide
                        $string72_burpsuite_offensive_tool_keyword = /portswigger\.net/ nocase ascii wide
                        $string73_burpsuite_offensive_tool_keyword = "PortSwigger/http-request-smuggler" nocase ascii wide
                        $string74_burpsuite_offensive_tool_keyword = /RequestAsPython\-PowerShell\.py/ nocase ascii wide
                        $string75_burpsuite_offensive_tool_keyword = /sqlmap4burp.{0,1000}\.jar/ nocase ascii wide
                        $string76_burpsuite_offensive_tool_keyword = /sshbrute\.py/ nocase ascii wide
                        $string77_burpsuite_offensive_tool_keyword = /struts_ext_v2\.jar/ nocase ascii wide

    condition:
        any of them
}