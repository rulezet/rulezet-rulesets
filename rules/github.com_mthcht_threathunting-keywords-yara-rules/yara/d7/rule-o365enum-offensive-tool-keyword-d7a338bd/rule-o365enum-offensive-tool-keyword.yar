rule rule_o365enum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'o365enum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "o365enum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_o365enum_offensive_tool_keyword = "1c50adeb-53ac-41b9-9c34-7045cffbae45" nocase ascii wide
                        $string2_o365enum_offensive_tool_keyword = "23975ac9-f51c-443a-8318-db006fd83100" nocase ascii wide
                        $string3_o365enum_offensive_tool_keyword = "2944dbfc-8a1e-4759-a8a2-e4568950601d" nocase ascii wide
                        $string4_o365enum_offensive_tool_keyword = "aW52YWxpZF91c2VyQGNvbnRvc28uY29tOlBhc3N3b3JkMQ" nocase ascii wide
                        $string5_o365enum_offensive_tool_keyword = "c708b83f-4167-4b4c-a1db-d2011ecb3200" nocase ascii wide
                        $string6_o365enum_offensive_tool_keyword = "d494a4bc-3867-436a-93ef-737f9e0522eb" nocase ascii wide
                        $string7_o365enum_offensive_tool_keyword = "dmFsaWRfdXNlckBjb250b3NvLmNvbTpQYXNzd29yZDE" nocase ascii wide
                        $string8_o365enum_offensive_tool_keyword = "fea01b74-7a60-4142-a54d-7aa8f6471c00" nocase ascii wide
                        $string9_o365enum_offensive_tool_keyword = "gremwell/o365enum" nocase ascii wide
                        $string10_o365enum_offensive_tool_keyword = /o365enum\.py/ nocase ascii wide
                        $string11_o365enum_offensive_tool_keyword = "o365enum-master" nocase ascii wide
                        $string12_o365enum_offensive_tool_keyword = /valid_user\@contoso\.com\:Password1/ nocase ascii wide

    condition:
        any of them
}