rule rdp
{
    meta:
        description = "Detection patterns for the tool 'rdp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\Content\\\.Outlook\\.{0,1000}\\.{0,1000}\.rdp/ nocase ascii wide

    condition:
        any of them
}