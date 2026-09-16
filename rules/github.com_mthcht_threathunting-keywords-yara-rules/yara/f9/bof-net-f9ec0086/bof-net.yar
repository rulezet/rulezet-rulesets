rule BOF_NET
{
    meta:
        description = "Detection patterns for the tool 'BOF.NET' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BOF.NET"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /BOF\.NET\.git/ nocase ascii wide
                        $string2 = /BOF\.NET\-main/ nocase ascii wide

    condition:
        any of them
}