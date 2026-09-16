rule rule_pyshark_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pyshark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyshark"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pyshark_greyware_tool_keyword = /\/pyshark\.git/ nocase ascii wide
                        $string2_pyshark_greyware_tool_keyword = /\\pyshark\\src\\/ nocase ascii wide
                        $string3_pyshark_greyware_tool_keyword = "import pyshark" nocase ascii wide
                        $string4_pyshark_greyware_tool_keyword = "KimiNewt/pyshark" nocase ascii wide
                        $string5_pyshark_greyware_tool_keyword = "pip install pyshark" nocase ascii wide
                        $string6_pyshark_greyware_tool_keyword = /pyshark\.FileCapture\(/ nocase ascii wide
                        $string7_pyshark_greyware_tool_keyword = /pyshark\.LiveCapture\(/ nocase ascii wide
                        $string8_pyshark_greyware_tool_keyword = /pyshark\.RemoteCapture\(/ nocase ascii wide

    condition:
        any of them
}