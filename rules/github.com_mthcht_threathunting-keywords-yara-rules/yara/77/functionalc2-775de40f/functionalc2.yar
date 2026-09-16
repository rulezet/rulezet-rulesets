rule FunctionalC2
{
    meta:
        description = "Detection patterns for the tool 'FunctionalC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FunctionalC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/FunctionalC2/" nocase ascii wide
                        $string2 = /beacon_endpoint.{0,1000}c2Get/ nocase ascii wide
                        $string3 = /beacon_endpoint.{0,1000}c2Post/ nocase ascii wide
                        $string4 = "FortyNorthSecurity/FunctionalC2" nocase ascii wide
                        $string5 = /gcp_functionalc2\.profile/ nocase ascii wide
                        $string6 = /http\:\/\/.{0,1000}\/FortyNorth\/GetIt/ nocase ascii wide
                        $string7 = /http\:\/\/.{0,1000}\/FortyNorth\/PostIt/ nocase ascii wide

    condition:
        any of them
}