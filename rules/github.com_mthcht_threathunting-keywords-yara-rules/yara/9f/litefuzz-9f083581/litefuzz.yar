rule litefuzz
{
    meta:
        description = "Detection patterns for the tool 'litefuzz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "litefuzz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/litefuzz\.py/
                        $string2 = "/sec-tools/litefuzz" nocase ascii wide
                        $string3 = /AcroRd32\.exe\sFUZZ/ nocase ascii wide
                        $string4 = "antiword FUZZ" nocase ascii wide
                        $string5 = "litefuzz -lk -c" nocase ascii wide
                        $string6 = "litefuzz -s -a " nocase ascii wide
                        $string7 = /litefuzz.{0,1000}\s\-l\s\-c/ nocase ascii wide
                        $string8 = /litefuzz\.py\s/ nocase ascii wide
                        $string9 = /litefuzz\\fuzz\.py/ nocase ascii wide
                        $string10 = "--mutator N" nocase ascii wide
                        $string11 = /mutator\.py\s/ nocase ascii wide
                        $string12 = "notepad FUZZ" nocase ascii wide
                        $string13 = /puttygen\.exe\sFUZZ/ nocase ascii wide
                        $string14 = /test_litefuzz\.py/ nocase ascii wide

    condition:
        any of them
}