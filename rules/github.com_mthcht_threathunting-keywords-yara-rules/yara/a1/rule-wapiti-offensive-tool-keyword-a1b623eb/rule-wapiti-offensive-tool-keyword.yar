rule rule_wapiti_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wapiti' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wapiti"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wapiti_offensive_tool_keyword = " --flush-attacks" nocase ascii wide
                        $string2_wapiti_offensive_tool_keyword = " install wapiti3" nocase ascii wide
                        $string3_wapiti_offensive_tool_keyword = " --max-attack-time" nocase ascii wide
                        $string4_wapiti_offensive_tool_keyword = " --skip-crawl" nocase ascii wide
                        $string5_wapiti_offensive_tool_keyword = "/bin/wapiti"
                        $string6_wapiti_offensive_tool_keyword = /\/data\/attacks\/.{0,1000}\.txt/ nocase ascii wide
                        $string7_wapiti_offensive_tool_keyword = "/wapitiCore/" nocase ascii wide
                        $string8_wapiti_offensive_tool_keyword = "/wapiti-scanner/" nocase ascii wide
                        $string9_wapiti_offensive_tool_keyword = /blindSQLPayloads\.txt/ nocase ascii wide
                        $string10_wapiti_offensive_tool_keyword = /busterPayloads\.txt/ nocase ascii wide
                        $string11_wapiti_offensive_tool_keyword = "downloads/wapiti-code" nocase ascii wide
                        $string12_wapiti_offensive_tool_keyword = /drupal_enum\.py/ nocase ascii wide
                        $string13_wapiti_offensive_tool_keyword = /execPayloads\.txt/ nocase ascii wide
                        $string14_wapiti_offensive_tool_keyword = /from\swapitiCore\./ nocase ascii wide
                        $string15_wapiti_offensive_tool_keyword = "import wapiti" nocase ascii wide
                        $string16_wapiti_offensive_tool_keyword = "install wapiti" nocase ascii wide
                        $string17_wapiti_offensive_tool_keyword = /log4shell\.py/ nocase ascii wide
                        $string18_wapiti_offensive_tool_keyword = /mod_buster\.py/ nocase ascii wide
                        $string19_wapiti_offensive_tool_keyword = /mod_nikto\.py/ nocase ascii wide
                        $string20_wapiti_offensive_tool_keyword = /mod_shellshock\.py/ nocase ascii wide
                        $string21_wapiti_offensive_tool_keyword = /mod_wp_enum\.py/ nocase ascii wide
                        $string22_wapiti_offensive_tool_keyword = /sql_persister\.py/ nocase ascii wide
                        $string23_wapiti_offensive_tool_keyword = /subdomain_takeovers\.py/ nocase ascii wide
                        $string24_wapiti_offensive_tool_keyword = /subdomain\-wordlist\.txt/ nocase ascii wide
                        $string25_wapiti_offensive_tool_keyword = /test_crawler\.py/ nocase ascii wide
                        $string26_wapiti_offensive_tool_keyword = "venv wapiti3" nocase ascii wide
                        $string27_wapiti_offensive_tool_keyword = "wapiti -u" nocase ascii wide
                        $string28_wapiti_offensive_tool_keyword = /wapiti\.git/ nocase ascii wide
                        $string29_wapiti_offensive_tool_keyword = /wapiti\.py/ nocase ascii wide
                        $string30_wapiti_offensive_tool_keyword = /wapiti3\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string31_wapiti_offensive_tool_keyword = /wapiti3\-.{0,1000}\-any\.whl/ nocase ascii wide
                        $string32_wapiti_offensive_tool_keyword = "wapiti3/bin" nocase ascii wide
                        $string33_wapiti_offensive_tool_keyword = "wapiti-getcookie" nocase ascii wide
                        $string34_wapiti_offensive_tool_keyword = /wappalyzer\.py/ nocase ascii wide
                        $string35_wapiti_offensive_tool_keyword = /xxePayloads\.ini/ nocase ascii wide

    condition:
        any of them
}