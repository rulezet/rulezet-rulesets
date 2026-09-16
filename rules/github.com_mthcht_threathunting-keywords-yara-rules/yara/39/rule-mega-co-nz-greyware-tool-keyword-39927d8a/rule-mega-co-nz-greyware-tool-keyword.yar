rule rule_mega_co_nz_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mega.co.nz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mega.co.nz"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_mega_co_nz_greyware_tool_keyword = /\.userstorage\.mega\.co\.nz\/ul\// nocase ascii wide

    condition:
        any of them
}