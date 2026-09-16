rule rule_litefuzz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'litefuzz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "litefuzz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_litefuzz_offensive_tool_keyword = /\.\/litefuzz\.py/
                        $string2_litefuzz_offensive_tool_keyword = "/sec-tools/litefuzz" nocase ascii wide
                        $string3_litefuzz_offensive_tool_keyword = /AcroRd32\.exe\sFUZZ/ nocase ascii wide
                        $string4_litefuzz_offensive_tool_keyword = "antiword FUZZ" nocase ascii wide
                        $string5_litefuzz_offensive_tool_keyword = "litefuzz -lk -c" nocase ascii wide
                        $string6_litefuzz_offensive_tool_keyword = "litefuzz -s -a " nocase ascii wide
                        $string7_litefuzz_offensive_tool_keyword = /litefuzz.{0,1000}\s\-l\s\-c/ nocase ascii wide
                        $string8_litefuzz_offensive_tool_keyword = /litefuzz\.py\s/ nocase ascii wide
                        $string9_litefuzz_offensive_tool_keyword = /litefuzz\\fuzz\.py/ nocase ascii wide
                        $string10_litefuzz_offensive_tool_keyword = "--mutator N" nocase ascii wide
                        $string11_litefuzz_offensive_tool_keyword = /mutator\.py\s/ nocase ascii wide
                        $string12_litefuzz_offensive_tool_keyword = "notepad FUZZ" nocase ascii wide
                        $string13_litefuzz_offensive_tool_keyword = /puttygen\.exe\sFUZZ/ nocase ascii wide
                        $string14_litefuzz_offensive_tool_keyword = /test_litefuzz\.py/ nocase ascii wide

    condition:
        any of them
}