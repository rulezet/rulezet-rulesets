rule burpsuite
{
    meta:
        description = "Detection patterns for the tool 'burpsuite' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "burpsuite"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sDigitalOceanProxyTab\.java/ nocase ascii wide
                        $string2 = "/awesome-burp-extensions/" nocase ascii wide
                        $string3 = "/burp/releases/community/latest" nocase ascii wide
                        $string4 = "/burp-api/" nocase ascii wide
                        $string5 = /\/BurpExtender\.java/ nocase ascii wide
                        $string6 = "/BurpSuite-collections" nocase ascii wide
                        $string7 = "/co2-cewler/" nocase ascii wide
                        $string8 = "/co2-core/" nocase ascii wide
                        $string9 = "/co2-laudanum/" nocase ascii wide
                        $string10 = "/co2-sqlmapper/" nocase ascii wide
                        $string11 = /\/DigitalOceanProxyTab\.java/ nocase ascii wide
                        $string12 = "/http-request-smuggler/" nocase ascii wide
                        $string13 = "/laconicwolf/burp-extensions" nocase ascii wide
                        $string14 = /\/turbo\-intruder\-all\.jar/ nocase ascii wide
                        $string15 = /\\DigitalOceanProxyTab\.java/ nocase ascii wide
                        $string16 = /\\http\-request\-smuggler\\/ nocase ascii wide
                        $string17 = /\\turbo\-intruder\-all\.jar/ nocase ascii wide
                        $string18 = "4955d7e8fc3d3ded8e3b95757c78b3c4cd969b5fbb92a65267e6141b8faa83d5" nocase ascii wide
                        $string19 = "Burp Suite" nocase ascii wide
                        $string20 = /burp.{0,1000}PayloadParser\.py/ nocase ascii wide
                        $string21 = /burp.{0,1000}SQLMapper\.xml/ nocase ascii wide
                        $string22 = /burp\.extension\-payloadparser/ nocase ascii wide
                        $string23 = /Burp_start\.bat/ nocase ascii wide
                        $string24 = /Burp_start_en\.bat/ nocase ascii wide
                        $string25 = "burp-co2/out/artifacts" nocase ascii wide
                        $string26 = /BurpCO2Suite\.xml/ nocase ascii wide
                        $string27 = /burpcollaborator\.net/ nocase ascii wide
                        $string28 = /BurpFunctions\.java/ nocase ascii wide
                        $string29 = /BurpShiroPassiveScan\.jar/ nocase ascii wide
                        $string30 = "Burpsuite" nocase ascii wide
                        $string31 = /burpsuite.{0,1000}\.exe/ nocase ascii wide
                        $string32 = /burpsuite.{0,1000}\.jar/ nocase ascii wide
                        $string33 = /burpsuite.{0,1000}\.sh/ nocase ascii wide
                        $string34 = /burpsuite.{0,1000}\.zip/ nocase ascii wide
                        $string35 = /BurpSuiteCn\.jar/ nocase ascii wide
                        $string36 = "BurpSuiteHTTPSmuggler" nocase ascii wide
                        $string37 = /burp\-vulners\-scanner\-.{0,1000}\.jar/ nocase ascii wide
                        $string38 = "burp-xss-sql-plugin" nocase ascii wide
                        $string39 = /bypasswaf\.jar/ nocase ascii wide
                        $string40 = /captcha\-killer\..{0,1000}\.jar/ nocase ascii wide
                        $string41 = "CN=PortSwigger" nocase ascii wide
                        $string42 = "Creating DigitalOcean OVPN Proxy tab" nocase ascii wide
                        $string43 = "Destroying all droplets" nocase ascii wide
                        $string44 = /digitalocean\-droplet\-openvpn\-all\.jar/ nocase ascii wide
                        $string45 = /DigitalOceanProxyTab\$1\.class/ nocase ascii wide
                        $string46 = /domain_hunter\-v.{0,1000}\.jar/ nocase ascii wide
                        $string47 = /FastjsonScan\.jar/ nocase ascii wide
                        $string48 = "Generated random password for socks proxy:" nocase ascii wide
                        $string49 = /GenerateForcedBrowseWordlist\.py/ nocase ascii wide
                        $string50 = /GenerateParameterWordlist\.py/ nocase ascii wide
                        $string51 = /http\:\/\/.{0,1000}\.oast\.fun\// nocase ascii wide
                        $string52 = /http\:\/\/.{0,1000}\.oast\.live\// nocase ascii wide
                        $string53 = /http\:\/\/.{0,1000}\.oast\.me\// nocase ascii wide
                        $string54 = /http\:\/\/.{0,1000}\.oast\.online\// nocase ascii wide
                        $string55 = /http\:\/\/.{0,1000}\.oast\.pro\// nocase ascii wide
                        $string56 = /http\:\/\/.{0,1000}\.oast\.site\// nocase ascii wide
                        $string57 = /http\:\/\/.{0,1000}\.oastify\.com\// nocase ascii wide
                        $string58 = /http\-request\-smuggler\-all\.jar/ nocase ascii wide
                        $string59 = /httpsmuggler\.jar/ nocase ascii wide
                        $string60 = /IBurpExtender\.java/ nocase ascii wide
                        $string61 = /IBurpExtenderCallbacks\.java/ nocase ascii wide
                        $string62 = /InjectMate\.py/ nocase ascii wide
                        $string63 = /InjectMateCommunity\.py/ nocase ascii wide
                        $string64 = /IntruderPayloadGeneratorFactory\.class/ nocase ascii wide
                        $string65 = /IntruderPayloadProcessor\.class/ nocase ascii wide
                        $string66 = "JGillam/burp-co2" nocase ascii wide
                        $string67 = /LFI\sscanner\schecks\.jar/ nocase ascii wide
                        $string68 = /MakeHTTPSmugglerJAR\.launch/ nocase ascii wide
                        $string69 = /OpenVPN\/SOCKS\sextension\sinitialized\./ nocase ascii wide
                        $string70 = /perfdata\.portswigger\.net/ nocase ascii wide
                        $string71 = /portswigger\.net/ nocase ascii wide
                        $string72 = /portswigger\.net/ nocase ascii wide
                        $string73 = "PortSwigger/http-request-smuggler" nocase ascii wide
                        $string74 = /RequestAsPython\-PowerShell\.py/ nocase ascii wide
                        $string75 = /sqlmap4burp.{0,1000}\.jar/ nocase ascii wide
                        $string76 = /sshbrute\.py/ nocase ascii wide
                        $string77 = /struts_ext_v2\.jar/ nocase ascii wide

    condition:
        any of them
}