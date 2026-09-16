rule rule_NimDllSideload_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NimDllSideload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimDllSideload"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NimDllSideload_offensive_tool_keyword = /\/dllproxy\.nim/ nocase ascii wide
                        $string2_NimDllSideload_offensive_tool_keyword = /\/NimDllSideload\.git/ nocase ascii wide
                        $string3_NimDllSideload_offensive_tool_keyword = "/NimDllSideload/" nocase ascii wide
                        $string4_NimDllSideload_offensive_tool_keyword = /\\dllproxy\.nim/ nocase ascii wide
                        $string5_NimDllSideload_offensive_tool_keyword = /\\NimDllSideload\\/ nocase ascii wide
                        $string6_NimDllSideload_offensive_tool_keyword = "a0acc8bea0d7e8ecacd1b7545e073b7575c28ad9be6464e1e756ba63084b9cd0" nocase ascii wide
                        $string7_NimDllSideload_offensive_tool_keyword = /app\/dllproxy\.nim/ nocase ascii wide
                        $string8_NimDllSideload_offensive_tool_keyword = "byt3bl33d3r/NimDllSideload" nocase ascii wide
                        $string9_NimDllSideload_offensive_tool_keyword = "make image && make proxydll" nocase ascii wide
                        $string10_NimDllSideload_offensive_tool_keyword = "NimDllSideload-main" nocase ascii wide

    condition:
        any of them
}