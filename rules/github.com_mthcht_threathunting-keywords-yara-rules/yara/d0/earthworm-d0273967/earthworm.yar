rule EarthWorm
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "signature_keyword"

    strings:
                        $string1 = "ELF:Earthworm-B" nocase ascii wide
                        $string2 = /HackTool\.EarthWorm/ nocase ascii wide
                        $string3 = /Hacktool\.Earthworm/ nocase ascii wide
                        $string4 = /HackTool\.Linux\.EarthWorm/ nocase ascii wide
                        $string5 = /HackTool\.Win32\.Earthworm/ nocase ascii wide
                        $string6 = /HackTool\/Win32\.Earthworm/ nocase ascii wide
                        $string7 = "HackTool:Linux/EarthWorm" nocase ascii wide
                        $string8 = /Linux\.Hacktool\.Earthworm/ nocase ascii wide
                        $string9 = /Tool\.Linux\.EarthWorm/ nocase ascii wide
                        $string10 = /Win\.Tool\.Earthworm\-/ nocase ascii wide

    condition:
        any of them
}