rule rule_psloggedon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'psloggedon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psloggedon"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_psloggedon_greyware_tool_keyword = /PsLoggedon\.exe/ nocase ascii wide
                        $string2_psloggedon_greyware_tool_keyword = /PsLoggedon64\.exe/ nocase ascii wide

    condition:
        any of them
}