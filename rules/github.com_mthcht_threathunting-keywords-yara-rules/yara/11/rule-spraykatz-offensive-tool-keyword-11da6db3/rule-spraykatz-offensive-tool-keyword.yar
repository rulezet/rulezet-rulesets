rule rule_spraykatz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spraykatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spraykatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spraykatz_offensive_tool_keyword = /\sPrintCreds\.py/ nocase ascii wide
                        $string2_spraykatz_offensive_tool_keyword = /\sSprayLove\.py/ nocase ascii wide
                        $string3_spraykatz_offensive_tool_keyword = /\.dmp\s1\>\s\\\\127\.0\.0\.1\\C\$\\/ nocase ascii wide
                        $string4_spraykatz_offensive_tool_keyword = /\/PrintCreds\.py/ nocase ascii wide
                        $string5_spraykatz_offensive_tool_keyword = /\/SprayLove\.py/ nocase ascii wide
                        $string6_spraykatz_offensive_tool_keyword = /\\PrintCreds\.py/ nocase ascii wide
                        $string7_spraykatz_offensive_tool_keyword = /\\SprayLove\.py/ nocase ascii wide
                        $string8_spraykatz_offensive_tool_keyword = "2fe32ea10b81598147f6d39cc0ae54a03a5384c73d1fba22fc3f9ae6589ec266" nocase ascii wide
                        $string9_spraykatz_offensive_tool_keyword = "335f1dcefb6d0e3e4a2e97d68d54d87cb53f6ba029a428a048752b19ecca71ad" nocase ascii wide
                        $string10_spraykatz_offensive_tool_keyword = "5e5e21abed5ff9e25cd2ea1c626a1f0ffe6194d1e2c74dfec8aebc0789b2dee1" nocase ascii wide
                        $string11_spraykatz_offensive_tool_keyword = "896106aa70f9ffdb5b219cbc1abcbdcff59bf05a339dcf9a2b9e095160f59e98" nocase ascii wide
                        $string12_spraykatz_offensive_tool_keyword = "be76da790e34b58cd8f35913154aa4d4a749372918cd00324993370bd086ba5a" nocase ascii wide
                        $string13_spraykatz_offensive_tool_keyword = /C\:\\\\SPRAY_.{0,1000}\.dmp/ nocase ascii wide
                        $string14_spraykatz_offensive_tool_keyword = /C\:\\SPRAY_.{0,1000}\.dmp/ nocase ascii wide
                        $string15_spraykatz_offensive_tool_keyword = /customWmiExec.{0,1000}wmiexec\.py/ nocase ascii wide
                        $string16_spraykatz_offensive_tool_keyword = "efe42a7eb08755abbb5c91b36ead35cdafbd82d1e34016046cb4be5861cb2053" nocase ascii wide
                        $string17_spraykatz_offensive_tool_keyword = /listLocalAdminAccess\(/ nocase ascii wide
                        $string18_spraykatz_offensive_tool_keyword = /listPwnableTargets\(/ nocase ascii wide
                        $string19_spraykatz_offensive_tool_keyword = "nmap -T3 -sT -Pn -n --open -p135 -oG -" nocase ascii wide
                        $string20_spraykatz_offensive_tool_keyword = /No\spwnable\stargets\.\sQuitting\./ nocase ascii wide
                        $string21_spraykatz_offensive_tool_keyword = /pypykatz\.pypykatz/ nocase ascii wide
                        $string22_spraykatz_offensive_tool_keyword = "spraykatz" nocase ascii wide
                        $string23_spraykatz_offensive_tool_keyword = /submodules\.pywerview\.requester/ nocase ascii wide
                        $string24_spraykatz_offensive_tool_keyword = /tasklist\s\/fi\s.{0,1000}Imagename\seq\slsass\.exe.{0,1000}do\sprocdump/ nocase ascii wide

    condition:
        any of them
}