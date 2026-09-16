rule rule_pysnaffler_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pysnaffler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysnaffler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pysnaffler_offensive_tool_keyword = /\ssnaffler\.py\s/ nocase ascii wide
                        $string2_pysnaffler_offensive_tool_keyword = /\.\/snaffler_downloads/
                        $string3_pysnaffler_offensive_tool_keyword = /\/pysnaffler\.git/ nocase ascii wide
                        $string4_pysnaffler_offensive_tool_keyword = /\/snaffler\.py/ nocase ascii wide
                        $string5_pysnaffler_offensive_tool_keyword = /\\pysnaffler\\pysnaffler\\/ nocase ascii wide
                        $string6_pysnaffler_offensive_tool_keyword = /\\snaffler\.py/ nocase ascii wide
                        $string7_pysnaffler_offensive_tool_keyword = /from\spysnaffler\.rules\.constants\simport\s/ nocase ascii wide
                        $string8_pysnaffler_offensive_tool_keyword = /from\spysnaffler\.rules\.rule\simport\sSnaffleRule/ nocase ascii wide
                        $string9_pysnaffler_offensive_tool_keyword = /from\spysnaffler\.ruleset\simport\sSnafflerRuleSet/ nocase ascii wide
                        $string10_pysnaffler_offensive_tool_keyword = /from\spysnaffler\.scanner\simport\sSnafflerScanner/ nocase ascii wide
                        $string11_pysnaffler_offensive_tool_keyword = /from\spysnaffler\.snaffler\simport\s/ nocase ascii wide
                        $string12_pysnaffler_offensive_tool_keyword = "pysnaffler -" nocase ascii wide
                        $string13_pysnaffler_offensive_tool_keyword = /pysnaffler\s\'smb2\+kerberos\+password\:/ nocase ascii wide
                        $string14_pysnaffler_offensive_tool_keyword = /pysnaffler\s\'smb2\+ntlm\-nt\:\/\// nocase ascii wide
                        $string15_pysnaffler_offensive_tool_keyword = /pysnaffler\s\'smb2\+ntlm\-password\:\/\// nocase ascii wide
                        $string16_pysnaffler_offensive_tool_keyword = /pysnaffler\.whatif\:main/ nocase ascii wide
                        $string17_pysnaffler_offensive_tool_keyword = /pysnaffler\/_version\.py/ nocase ascii wide
                        $string18_pysnaffler_offensive_tool_keyword = "pysnaffler-main" nocase ascii wide
                        $string19_pysnaffler_offensive_tool_keyword = "skelsec/pysnaffler" nocase ascii wide

    condition:
        any of them
}