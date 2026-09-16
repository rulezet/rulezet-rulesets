rule rule_PSRecon_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSRecon_offensive_tool_keyword = /\\PSRecon\\/ nocase ascii wide
                        $string2_PSRecon_offensive_tool_keyword = "Invoke-Recon " nocase ascii wide
                        $string3_PSRecon_offensive_tool_keyword = /PSRecon\.ps1/ nocase ascii wide

    condition:
        any of them
}