rule pysnaffler
{
    meta:
        description = "Detection patterns for the tool 'pysnaffler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysnaffler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\ssnaffler\.py\s/ nocase ascii wide
                        $string2 = /\.\/snaffler_downloads/
                        $string3 = /\/pysnaffler\.git/ nocase ascii wide
                        $string4 = /\/snaffler\.py/ nocase ascii wide
                        $string5 = /\\pysnaffler\\pysnaffler\\/ nocase ascii wide
                        $string6 = /\\snaffler\.py/ nocase ascii wide
                        $string7 = /from\spysnaffler\.rules\.constants\simport\s/ nocase ascii wide
                        $string8 = /from\spysnaffler\.rules\.rule\simport\sSnaffleRule/ nocase ascii wide
                        $string9 = /from\spysnaffler\.ruleset\simport\sSnafflerRuleSet/ nocase ascii wide
                        $string10 = /from\spysnaffler\.scanner\simport\sSnafflerScanner/ nocase ascii wide
                        $string11 = /from\spysnaffler\.snaffler\simport\s/ nocase ascii wide
                        $string12 = "pysnaffler -" nocase ascii wide
                        $string13 = /pysnaffler\s\'smb2\+kerberos\+password\:/ nocase ascii wide
                        $string14 = /pysnaffler\s\'smb2\+ntlm\-nt\:\/\// nocase ascii wide
                        $string15 = /pysnaffler\s\'smb2\+ntlm\-password\:\/\// nocase ascii wide
                        $string16 = /pysnaffler\.whatif\:main/ nocase ascii wide
                        $string17 = /pysnaffler\/_version\.py/ nocase ascii wide
                        $string18 = "pysnaffler-main" nocase ascii wide
                        $string19 = "skelsec/pysnaffler" nocase ascii wide

    condition:
        any of them
}