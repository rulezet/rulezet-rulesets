rule rule_Volumiser_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Volumiser' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Volumiser"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Volumiser_offensive_tool_keyword = /\sVolumiser\.exe\s/ nocase ascii wide
                        $string2_Volumiser_offensive_tool_keyword = "/CCob/Volumiser" nocase ascii wide
                        $string3_Volumiser_offensive_tool_keyword = /\/Volumiser\.exe/ nocase ascii wide
                        $string4_Volumiser_offensive_tool_keyword = /\/Volumiser\.git/ nocase ascii wide
                        $string5_Volumiser_offensive_tool_keyword = /\/Volumiser\-maser\.zip/ nocase ascii wide
                        $string6_Volumiser_offensive_tool_keyword = /\\Volumiser\.exe/ nocase ascii wide
                        $string7_Volumiser_offensive_tool_keyword = /\\Volumiser\.sln/ nocase ascii wide
                        $string8_Volumiser_offensive_tool_keyword = /\\Volumiser\\Program\.cs/ nocase ascii wide
                        $string9_Volumiser_offensive_tool_keyword = "0DF38AD4-60AF-4F93-9C7A-7FB7BA692017" nocase ascii wide
                        $string10_Volumiser_offensive_tool_keyword = /Volumiser\.exe\s\-\-image/ nocase ascii wide
                        $string11_Volumiser_offensive_tool_keyword = /Volumiser\\DiscUtils\.Ebs\\EbsMappedStream/ nocase ascii wide

    condition:
        any of them
}