rule rule_prefetch_tool_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'prefetch-tool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "prefetch-tool"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_prefetch_tool_offensive_tool_keyword = /\/prefetch\-tool\.git/ nocase ascii wide
                        $string2_prefetch_tool_offensive_tool_keyword = /\\prefetch_leak\.h/ nocase ascii wide
                        $string3_prefetch_tool_offensive_tool_keyword = /\\prefetch_tool\.sln/ nocase ascii wide
                        $string4_prefetch_tool_offensive_tool_keyword = /\\prefetch_tool\.vcxproj/ nocase ascii wide
                        $string5_prefetch_tool_offensive_tool_keyword = "82ac960f25131540ae230b2bac0f003ffc8edc8a05382d8831ff8e8ebf30996d" nocase ascii wide
                        $string6_prefetch_tool_offensive_tool_keyword = "8aba74be7acef3c84cef0163411298aa994872347a4ac84cc0a0d19ddf0eb65c" nocase ascii wide
                        $string7_prefetch_tool_offensive_tool_keyword = "A46C9A13-145E-42C0-8CA6-CC920BF1D9F1" nocase ascii wide
                        $string8_prefetch_tool_offensive_tool_keyword = "exploits-forsale/prefetch-tool" nocase ascii wide
                        $string9_prefetch_tool_offensive_tool_keyword = /include\s\\"prefetch_leak\.h\\"/ nocase ascii wide
                        $string10_prefetch_tool_offensive_tool_keyword = /lallousz\-x86\@yahoo\.com/ nocase ascii wide

    condition:
        any of them
}