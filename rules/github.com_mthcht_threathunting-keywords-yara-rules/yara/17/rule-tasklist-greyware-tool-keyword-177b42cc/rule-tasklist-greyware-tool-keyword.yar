rule rule_tasklist_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tasklist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tasklist"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tasklist_greyware_tool_keyword = /tasklist\s\/fi\s.{0,1000}Imagename\seq\slsass\.exe/ nocase ascii wide
                        $string2_tasklist_greyware_tool_keyword = /tasklist\s\/svc\s\|\sfindstr\s\/i\s\\"vmtoolsd\.exe\\"/ nocase ascii wide
                        $string3_tasklist_greyware_tool_keyword = /tasklist\s\|\sfindstr\slsass/ nocase ascii wide

    condition:
        any of them
}