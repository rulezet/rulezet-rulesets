rule PSRecon
{
    meta:
        description = "Detection patterns for the tool 'PSRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSRecon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\PSRecon\\/ nocase ascii wide
                        $string2 = "Invoke-Recon " nocase ascii wide
                        $string3 = /PSRecon\.ps1/ nocase ascii wide

    condition:
        any of them
}