rule HTTP_Shell
{
    meta:
        description = "Detection patterns for the tool 'HTTP-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HTTP-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HTTP\-Client\.sh/
                        $string2 = /\/HTTP\-Shell\.git/ nocase ascii wide
                        $string3 = /\/ps2exe\.ps1/ nocase ascii wide
                        $string4 = /\[\+\]\sDownloading\sPS2exe\sand\sgenerating\spayload/ nocase ascii wide
                        $string5 = /\[\+\]\sUploading\sto\sPS2exe\sand\sgenerating\spayload/ nocase ascii wide
                        $string6 = /\\HTTP\-Client\.ps1/ nocase ascii wide
                        $string7 = /\\HTTP\-Server\.py/ nocase ascii wide
                        $string8 = /\\PayloadGen\.ps1/ nocase ascii wide
                        $string9 = /\\ps2exe\.ps1/ nocase ascii wide
                        $string10 = "185d6eb2bb3eeef1bc1737f766942e215342c864bdfd6132c2d55f22a5a10d61" nocase ascii wide
                        $string11 = "340ebf838dd969bc96dde3068e57e62b30726e78bc663ef60ad6cbd7c5d8716a" nocase ascii wide
                        $string12 = "7d67b3f5a0eae10e93d144bd9dba056c77d14b3246aa86ca20d8de02b3f1c674" nocase ascii wide
                        $string13 = "f43e8c0cc98b12f28a0aa3548d67c78856c13292bfb06ecdfcbba5caefa9fef0" nocase ascii wide
                        $string14 = /HTTP\-Server\.py\s/ nocase ascii wide
                        $string15 = /invoke\-stealth\.php/ nocase ascii wide
                        $string16 = /Invoke\-Stealth\.ps1/ nocase ascii wide
                        $string17 = "JoelGMSec/HTTP-Shell" nocase ascii wide
                        $string18 = /PayloadGen\sv2\.0\s\-\sby\s\@JoelGMSec/ nocase ascii wide
                        $string19 = /Set\-Content\s\$PS2exePath/ nocase ascii wide

    condition:
        any of them
}