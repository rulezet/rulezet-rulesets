rule rule_SharpDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpDump_offensive_tool_keyword = /\/SharpDump\.exe/ nocase ascii wide
                        $string2_SharpDump_offensive_tool_keyword = /\/SharpDump\.git/ nocase ascii wide
                        $string3_SharpDump_offensive_tool_keyword = /\[X\]\sNot\sin\shigh\sintegrity\,\sunable\sto\sMiniDump\!/ nocase ascii wide
                        $string4_SharpDump_offensive_tool_keyword = /\\Out\-Minidump\.ps1/ nocase ascii wide
                        $string5_SharpDump_offensive_tool_keyword = /\\SharpDump\.csproj/ nocase ascii wide
                        $string6_SharpDump_offensive_tool_keyword = /\\SharpDump\.exe/ nocase ascii wide
                        $string7_SharpDump_offensive_tool_keyword = ">SharpDump<" nocase ascii wide
                        $string8_SharpDump_offensive_tool_keyword = "0a7cf0b0d8f68eec8829dde1d90183087d641547a6c97de021db9a631da99857" nocase ascii wide
                        $string9_SharpDump_offensive_tool_keyword = "79C9BBA3-A0EA-431C-866C-77004802D8A0" nocase ascii wide
                        $string10_SharpDump_offensive_tool_keyword = "7adf4cdaa2190d19969e9f2fe6315d586fd5b709466ef2c84379b8b3a595ffc8" nocase ascii wide
                        $string11_SharpDump_offensive_tool_keyword = "8ef62495d042ae030268ca52d01baece60c79f34d49a113ef5c2322e7041c053" nocase ascii wide
                        $string12_SharpDump_offensive_tool_keyword = "a829137b318890cb77f6a1ce28ce4dbaa4a39e19ef91b75f4f50dfc2b1a992bf" nocase ascii wide
                        $string13_SharpDump_offensive_tool_keyword = "GhostPack/SharpDump" nocase ascii wide
                        $string14_SharpDump_offensive_tool_keyword = "sekurlsa::logonPasswords full" nocase ascii wide
                        $string15_SharpDump_offensive_tool_keyword = /sekurlsa\:\:minidump\sdebug\.out/ nocase ascii wide

    condition:
        any of them
}