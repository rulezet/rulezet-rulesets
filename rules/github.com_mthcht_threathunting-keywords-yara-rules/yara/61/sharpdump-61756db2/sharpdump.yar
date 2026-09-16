rule SharpDump
{
    meta:
        description = "Detection patterns for the tool 'SharpDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpDump\.exe/ nocase ascii wide
                        $string2 = /\/SharpDump\.git/ nocase ascii wide
                        $string3 = /\[X\]\sNot\sin\shigh\sintegrity\,\sunable\sto\sMiniDump\!/ nocase ascii wide
                        $string4 = /\\Out\-Minidump\.ps1/ nocase ascii wide
                        $string5 = /\\SharpDump\.csproj/ nocase ascii wide
                        $string6 = /\\SharpDump\.exe/ nocase ascii wide
                        $string7 = ">SharpDump<" nocase ascii wide
                        $string8 = "0a7cf0b0d8f68eec8829dde1d90183087d641547a6c97de021db9a631da99857" nocase ascii wide
                        $string9 = "79C9BBA3-A0EA-431C-866C-77004802D8A0" nocase ascii wide
                        $string10 = "7adf4cdaa2190d19969e9f2fe6315d586fd5b709466ef2c84379b8b3a595ffc8" nocase ascii wide
                        $string11 = "8ef62495d042ae030268ca52d01baece60c79f34d49a113ef5c2322e7041c053" nocase ascii wide
                        $string12 = "a829137b318890cb77f6a1ce28ce4dbaa4a39e19ef91b75f4f50dfc2b1a992bf" nocase ascii wide
                        $string13 = "GhostPack/SharpDump" nocase ascii wide
                        $string14 = "sekurlsa::logonPasswords full" nocase ascii wide
                        $string15 = /sekurlsa\:\:minidump\sdebug\.out/ nocase ascii wide

    condition:
        any of them
}