rule rule_TDSKiller_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TDSKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TDSKiller"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_TDSKiller_greyware_tool_keyword = /\/TDSSKiller\.exe/ nocase ascii wide
                        $string2_TDSKiller_greyware_tool_keyword = /\/tdsskiller\.zip/ nocase ascii wide
                        $string3_TDSKiller_greyware_tool_keyword = /\\TDSSKiller\.exe/ nocase ascii wide
                        $string4_TDSKiller_greyware_tool_keyword = /\\tdsskiller\.zip/ nocase ascii wide
                        $string5_TDSKiller_greyware_tool_keyword = ">TDSS rootkit removing tool<" nocase ascii wide
                        $string6_TDSKiller_greyware_tool_keyword = ">TDSSKiller<" nocase ascii wide
                        $string7_TDSKiller_greyware_tool_keyword = "2d823c8b6076e932d696e8cb8a2c5c5df6d392526cba8e39b64c43635f683009" nocase ascii wide
                        $string8_TDSKiller_greyware_tool_keyword = /http\:\/\/support\.kaspersky\.com\/viruses\/tdsskiller\.xmlt/ nocase ascii wide
                        $string9_TDSKiller_greyware_tool_keyword = "tdsskiller -dcsvc " nocase ascii wide

    condition:
        any of them
}