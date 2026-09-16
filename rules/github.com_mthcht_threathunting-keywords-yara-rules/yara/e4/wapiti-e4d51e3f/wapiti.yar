rule wapiti
{
    meta:
        description = "Detection patterns for the tool 'wapiti' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wapiti"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --flush-attacks" nocase ascii wide
                        $string2 = " install wapiti3" nocase ascii wide
                        $string3 = " --max-attack-time" nocase ascii wide
                        $string4 = " --skip-crawl" nocase ascii wide
                        $string5 = "/bin/wapiti"
                        $string6 = /\/data\/attacks\/.{0,1000}\.txt/ nocase ascii wide
                        $string7 = "/wapitiCore/" nocase ascii wide
                        $string8 = "/wapiti-scanner/" nocase ascii wide
                        $string9 = /blindSQLPayloads\.txt/ nocase ascii wide
                        $string10 = /busterPayloads\.txt/ nocase ascii wide
                        $string11 = "downloads/wapiti-code" nocase ascii wide
                        $string12 = /drupal_enum\.py/ nocase ascii wide
                        $string13 = /execPayloads\.txt/ nocase ascii wide
                        $string14 = /from\swapitiCore\./ nocase ascii wide
                        $string15 = "import wapiti" nocase ascii wide
                        $string16 = "install wapiti" nocase ascii wide
                        $string17 = /log4shell\.py/ nocase ascii wide
                        $string18 = /mod_buster\.py/ nocase ascii wide
                        $string19 = /mod_nikto\.py/ nocase ascii wide
                        $string20 = /mod_shellshock\.py/ nocase ascii wide
                        $string21 = /mod_wp_enum\.py/ nocase ascii wide
                        $string22 = /sql_persister\.py/ nocase ascii wide
                        $string23 = /subdomain_takeovers\.py/ nocase ascii wide
                        $string24 = /subdomain\-wordlist\.txt/ nocase ascii wide
                        $string25 = /test_crawler\.py/ nocase ascii wide
                        $string26 = "venv wapiti3" nocase ascii wide
                        $string27 = "wapiti -u" nocase ascii wide
                        $string28 = /wapiti\.git/ nocase ascii wide
                        $string29 = /wapiti\.py/ nocase ascii wide
                        $string30 = /wapiti3\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string31 = /wapiti3\-.{0,1000}\-any\.whl/ nocase ascii wide
                        $string32 = "wapiti3/bin" nocase ascii wide
                        $string33 = "wapiti-getcookie" nocase ascii wide
                        $string34 = /wappalyzer\.py/ nocase ascii wide
                        $string35 = /xxePayloads\.ini/ nocase ascii wide

    condition:
        any of them
}