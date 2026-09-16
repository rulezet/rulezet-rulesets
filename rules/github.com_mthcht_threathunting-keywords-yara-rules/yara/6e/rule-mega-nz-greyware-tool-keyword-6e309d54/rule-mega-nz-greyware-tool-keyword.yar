rule rule_mega_nz_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mega.nz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mega.nz"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_mega_nz_greyware_tool_keyword = /https\:\/\/mega\.nz\/file\// nocase ascii wide
                        $string2_mega_nz_greyware_tool_keyword = /https\:\/\/mega\.nz\/folder\// nocase ascii wide

    condition:
        any of them
}