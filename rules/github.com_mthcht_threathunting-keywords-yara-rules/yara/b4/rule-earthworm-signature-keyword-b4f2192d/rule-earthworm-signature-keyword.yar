rule rule_EarthWorm_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "signature_keyword"

    strings:
                        $string1_EarthWorm_signature_keyword = "ELF:Earthworm-B" nocase ascii wide
                        $string2_EarthWorm_signature_keyword = /HackTool\.EarthWorm/ nocase ascii wide
                        $string3_EarthWorm_signature_keyword = /Hacktool\.Earthworm/ nocase ascii wide
                        $string4_EarthWorm_signature_keyword = /HackTool\.Linux\.EarthWorm/ nocase ascii wide
                        $string5_EarthWorm_signature_keyword = /HackTool\.Win32\.Earthworm/ nocase ascii wide
                        $string6_EarthWorm_signature_keyword = /HackTool\/Win32\.Earthworm/ nocase ascii wide
                        $string7_EarthWorm_signature_keyword = "HackTool:Linux/EarthWorm" nocase ascii wide
                        $string8_EarthWorm_signature_keyword = /Linux\.Hacktool\.Earthworm/ nocase ascii wide
                        $string9_EarthWorm_signature_keyword = /Tool\.Linux\.EarthWorm/ nocase ascii wide
                        $string10_EarthWorm_signature_keyword = /Win\.Tool\.Earthworm\-/ nocase ascii wide

    condition:
        any of them
}