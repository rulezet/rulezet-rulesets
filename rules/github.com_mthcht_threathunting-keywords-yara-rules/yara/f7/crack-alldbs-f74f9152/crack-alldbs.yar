rule Crack_allDBs
{
    meta:
        description = "Detection patterns for the tool 'Crack-allDBs' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Crack-allDBs"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /Crack\-allDBs\.git/ nocase ascii wide
                        $string2 = "Crack-allDBs-main" nocase ascii wide
                        $string3 = /crack\-allDBs\-v1\.py/ nocase ascii wide
                        $string4 = /crack\-allDBs\-v2\.py/ nocase ascii wide
                        $string5 = "d3ckx1/Crack-allDBs" nocase ascii wide

    condition:
        any of them
}