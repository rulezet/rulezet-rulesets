rule TDSKiller
{
    meta:
        description = "Detection patterns for the tool 'TDSKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TDSKiller"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/TDSSKiller\.exe/ nocase ascii wide
                        $string2 = /\/tdsskiller\.zip/ nocase ascii wide
                        $string3 = /\\TDSSKiller\.exe/ nocase ascii wide
                        $string4 = /\\tdsskiller\.zip/ nocase ascii wide
                        $string5 = ">TDSS rootkit removing tool<" nocase ascii wide
                        $string6 = ">TDSSKiller<" nocase ascii wide
                        $string7 = "2d823c8b6076e932d696e8cb8a2c5c5df6d392526cba8e39b64c43635f683009" nocase ascii wide
                        $string8 = /http\:\/\/support\.kaspersky\.com\/viruses\/tdsskiller\.xmlt/ nocase ascii wide
                        $string9 = "tdsskiller -dcsvc " nocase ascii wide

    condition:
        any of them
}