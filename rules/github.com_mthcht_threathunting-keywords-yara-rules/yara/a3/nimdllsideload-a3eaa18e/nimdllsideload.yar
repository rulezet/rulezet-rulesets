rule NimDllSideload
{
    meta:
        description = "Detection patterns for the tool 'NimDllSideload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NimDllSideload"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/dllproxy\.nim/ nocase ascii wide
                        $string2 = /\/NimDllSideload\.git/ nocase ascii wide
                        $string3 = "/NimDllSideload/" nocase ascii wide
                        $string4 = /\\dllproxy\.nim/ nocase ascii wide
                        $string5 = /\\NimDllSideload\\/ nocase ascii wide
                        $string6 = "a0acc8bea0d7e8ecacd1b7545e073b7575c28ad9be6464e1e756ba63084b9cd0" nocase ascii wide
                        $string7 = /app\/dllproxy\.nim/ nocase ascii wide
                        $string8 = "byt3bl33d3r/NimDllSideload" nocase ascii wide
                        $string9 = "make image && make proxydll" nocase ascii wide
                        $string10 = "NimDllSideload-main" nocase ascii wide

    condition:
        any of them
}