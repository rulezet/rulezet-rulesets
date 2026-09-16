rule FoxyProxy_Standard
{
    meta:
        description = "Detection patterns for the tool 'FoxyProxy Standard' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FoxyProxy Standard"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "gcknhkkoolaabfmlnjonogaaifnjlfnp" nocase ascii wide

    condition:
        any of them
}