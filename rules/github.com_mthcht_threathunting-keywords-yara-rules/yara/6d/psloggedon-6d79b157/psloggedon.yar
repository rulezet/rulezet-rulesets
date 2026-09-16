rule psloggedon
{
    meta:
        description = "Detection patterns for the tool 'psloggedon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psloggedon"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /PsLoggedon\.exe/ nocase ascii wide
                        $string2 = /PsLoggedon64\.exe/ nocase ascii wide

    condition:
        any of them
}