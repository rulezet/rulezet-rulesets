rule fltMC
{
    meta:
        description = "Detection patterns for the tool 'fltMC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fltMC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /fltMC.{0,1000}\sunload\sSysmonDrv/ nocase ascii wide

    condition:
        any of them
}