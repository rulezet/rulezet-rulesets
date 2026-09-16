rule rule_FunctionalC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FunctionalC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FunctionalC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FunctionalC2_offensive_tool_keyword = "/FunctionalC2/" nocase ascii wide
                        $string2_FunctionalC2_offensive_tool_keyword = /beacon_endpoint.{0,1000}c2Get/ nocase ascii wide
                        $string3_FunctionalC2_offensive_tool_keyword = /beacon_endpoint.{0,1000}c2Post/ nocase ascii wide
                        $string4_FunctionalC2_offensive_tool_keyword = "FortyNorthSecurity/FunctionalC2" nocase ascii wide
                        $string5_FunctionalC2_offensive_tool_keyword = /gcp_functionalc2\.profile/ nocase ascii wide
                        $string6_FunctionalC2_offensive_tool_keyword = /http\:\/\/.{0,1000}\/FortyNorth\/GetIt/ nocase ascii wide
                        $string7_FunctionalC2_offensive_tool_keyword = /http\:\/\/.{0,1000}\/FortyNorth\/PostIt/ nocase ascii wide

    condition:
        any of them
}