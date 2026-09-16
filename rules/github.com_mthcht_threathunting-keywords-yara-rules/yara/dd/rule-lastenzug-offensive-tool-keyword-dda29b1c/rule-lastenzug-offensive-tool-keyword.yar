rule rule_Lastenzug_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lastenzug' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lastenzug"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Lastenzug_offensive_tool_keyword = "! This is a sample loader for Lastenzug" nocase ascii wide
                        $string2_Lastenzug_offensive_tool_keyword = /\/LastenLoader\.exe/ nocase ascii wide
                        $string3_Lastenzug_offensive_tool_keyword = /\/Lastenzug\.git/ nocase ascii wide
                        $string4_Lastenzug_offensive_tool_keyword = /\\LastenLoader\.exe/ nocase ascii wide
                        $string5_Lastenzug_offensive_tool_keyword = /127\.0\.0\.1\:1337/ nocase ascii wide
                        $string6_Lastenzug_offensive_tool_keyword = "a07f5f82857dd9e0b02b4bb90783e028ff42e80fe8286dd2c8e983db138c3820" nocase ascii wide
                        $string7_Lastenzug_offensive_tool_keyword = /bin\/LastenPIC\.bin/ nocase ascii wide
                        $string8_Lastenzug_offensive_tool_keyword = "build -o LastenServer"
                        $string9_Lastenzug_offensive_tool_keyword = "codewhitesec/Lastenzug" nocase ascii wide
                        $string10_Lastenzug_offensive_tool_keyword = "d2807b9860e0e4801cd00f45421b5bcab30c1a818f193e4a3d33be8f65c99ea0" nocase ascii wide
                        $string11_Lastenzug_offensive_tool_keyword = "LastenPIC/SpiderPIC" nocase ascii wide
                        $string12_Lastenzug_offensive_tool_keyword = "LastenServer server "
                        $string13_Lastenzug_offensive_tool_keyword = "Lastenzug - PIC Socks4a proxy by @invist" nocase ascii wide
                        $string14_Lastenzug_offensive_tool_keyword = /ws\:\/\/127\.0\.0\.1\:1339\/yolo/ nocase ascii wide

    condition:
        any of them
}