rule rule_spoofing_office_macro_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'spoofing-office-macro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spoofing-office-macro"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_spoofing_office_macro_offensive_tool_keyword = /\/spoofing\-office\-macro\.git/ nocase ascii wide
                        $string2_spoofing_office_macro_offensive_tool_keyword = /\\macro64\.vba/ nocase ascii wide
                        $string3_spoofing_office_macro_offensive_tool_keyword = /\\spoofing\-office\-macro\-master/ nocase ascii wide
                        $string4_spoofing_office_macro_offensive_tool_keyword = "8b4cb728e2db083daf0b42a3d3e6982e161ba42f90264e6da1508800e4b4d394" nocase ascii wide
                        $string5_spoofing_office_macro_offensive_tool_keyword = "christophetd/spoofing-office-macro" nocase ascii wide
                        $string6_spoofing_office_macro_offensive_tool_keyword = /http\:\/\/bit\.ly\/2TxpA4h/ nocase ascii wide

    condition:
        any of them
}