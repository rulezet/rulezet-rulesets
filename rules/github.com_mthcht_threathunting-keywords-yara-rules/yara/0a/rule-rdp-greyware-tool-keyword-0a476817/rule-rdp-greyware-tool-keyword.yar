rule rule_rdp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rdp_greyware_tool_keyword = /\\Content\\\.Outlook\\.{0,1000}\\.{0,1000}\.rdp/ nocase ascii wide

    condition:
        any of them
}