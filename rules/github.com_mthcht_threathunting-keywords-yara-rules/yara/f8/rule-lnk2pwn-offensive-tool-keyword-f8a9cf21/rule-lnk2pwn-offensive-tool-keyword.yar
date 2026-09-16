rule rule_lnk2pwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lnk2pwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lnk2pwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lnk2pwn_offensive_tool_keyword = /\/lnk2pwn\.git/ nocase ascii wide
                        $string2_lnk2pwn_offensive_tool_keyword = /\/lnk2pwn\-1\.0\.0\.zip/ nocase ascii wide
                        $string3_lnk2pwn_offensive_tool_keyword = /\\Lnk2Pwn\.java/ nocase ascii wide
                        $string4_lnk2pwn_offensive_tool_keyword = /\\Lnk2PwnFrame\.java/ nocase ascii wide
                        $string5_lnk2pwn_offensive_tool_keyword = /\\lnk2pwn\-master/ nocase ascii wide
                        $string6_lnk2pwn_offensive_tool_keyword = /\\uac_bypass\.vbs/ nocase ascii wide
                        $string7_lnk2pwn_offensive_tool_keyword = "10c9d70217e5a3915a6c09feea4110991dae5d9a1b6ae5d32c4d69dd6b6eaf50" nocase ascii wide
                        $string8_lnk2pwn_offensive_tool_keyword = "7bc9e0e60db343690d6dcb61dd7f19c69fbd154234cbc38f7631f4a4a75fca8c" nocase ascii wide
                        $string9_lnk2pwn_offensive_tool_keyword = "98aa8eec1bda59ea57693a6312bae2b76b2e71dd29cd0f85453c3d867ec69394" nocase ascii wide
                        $string10_lnk2pwn_offensive_tool_keyword = /com\.itgorillaz\.lnk2pwn\.model/ nocase ascii wide
                        $string11_lnk2pwn_offensive_tool_keyword = "d1fccb8acadbdefaf27f8680c74c40dba94e52734dd9704d38c0de7b10066f14" nocase ascii wide
                        $string12_lnk2pwn_offensive_tool_keyword = "it-gorillaz/lnk2pwn" nocase ascii wide
                        $string13_lnk2pwn_offensive_tool_keyword = /Malicious\sShortcut\(\.lnk\)\sGenerator/ nocase ascii wide
                        $string14_lnk2pwn_offensive_tool_keyword = /UACBypassConfig\.java/ nocase ascii wide

    condition:
        any of them
}