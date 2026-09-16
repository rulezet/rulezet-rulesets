rule rule_potato_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'potato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "potato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_potato_offensive_tool_keyword = /\\Potato\.exe/ nocase ascii wide
                        $string2_potato_offensive_tool_keyword = /\\Potato\\obj\\Release\\Potato\.pdb/ nocase ascii wide
                        $string3_potato_offensive_tool_keyword = /127\.0\.0\.1\/C\$\/Windows\/System32\/utilman\.exe/ nocase ascii wide
                        $string4_potato_offensive_tool_keyword = "58ba7d7a43c3cbf5ffba7351a6509d04290b41ac5565735c6b6b66ffaf2daaca" nocase ascii wide
                        $string5_potato_offensive_tool_keyword = "7e21c5b9cf9cb3cc0b3c6909fdf3a7820c6feaa45e86722ed4e7a43d39aee819" nocase ascii wide
                        $string6_potato_offensive_tool_keyword = "893CC775-335D-4010-9751-D8C8E2A04048" nocase ascii wide
                        $string7_potato_offensive_tool_keyword = "c391bff39add68d2e9bd97ecfbc98850c2b80f831007df95704eedbc7e93617b" nocase ascii wide
                        $string8_potato_offensive_tool_keyword = "foxglovesec/Potato" nocase ascii wide
                        $string9_potato_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/wpad\.dat/ nocase ascii wide
                        $string10_potato_offensive_tool_keyword = /potato\.exe\s\-ip\s/ nocase ascii wide
                        $string11_potato_offensive_tool_keyword = "Starting NBNS spoofer" nocase ascii wide

    condition:
        any of them
}