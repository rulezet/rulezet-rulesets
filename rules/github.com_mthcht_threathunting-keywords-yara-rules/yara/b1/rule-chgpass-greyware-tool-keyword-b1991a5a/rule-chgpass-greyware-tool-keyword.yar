rule rule_chgpass_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chgpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chgpass"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_chgpass_greyware_tool_keyword = /chgpass\.exe.{0,1000}Administrator\s/ nocase ascii wide
                        $string2_chgpass_greyware_tool_keyword = /chgpass\.exe.{0,1000}DSRM/ nocase ascii wide

    condition:
        any of them
}