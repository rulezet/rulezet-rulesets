rule pyshark
{
    meta:
        description = "Detection patterns for the tool 'pyshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyshark"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/pyshark\.git/ nocase ascii wide
                        $string2 = /\\pyshark\\src\\/ nocase ascii wide
                        $string3 = "import pyshark" nocase ascii wide
                        $string4 = "KimiNewt/pyshark" nocase ascii wide
                        $string5 = "pip install pyshark" nocase ascii wide
                        $string6 = /pyshark\.FileCapture\(/ nocase ascii wide
                        $string7 = /pyshark\.LiveCapture\(/ nocase ascii wide
                        $string8 = /pyshark\.RemoteCapture\(/ nocase ascii wide

    condition:
        any of them
}