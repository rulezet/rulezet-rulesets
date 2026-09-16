rule PSAsyncShell
{
    meta:
        description = "Detection patterns for the tool 'PSAsyncShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAsyncShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPSAsyncShell\.ps1/ nocase ascii wide
                        $string2 = /\sPSAsyncShell\.sh/ nocase ascii wide
                        $string3 = /\/PSAsyncShell\.git/ nocase ascii wide
                        $string4 = /\/PSAsyncShell\.ps1/ nocase ascii wide
                        $string5 = /\/PSAsyncShell\.sh/ nocase ascii wide
                        $string6 = "/PSAsyncShell-main" nocase ascii wide
                        $string7 = /\[\+\]\sPSAsyncShell\sOK\!/ nocase ascii wide
                        $string8 = /\\PSAsyncShell\.ps1/ nocase ascii wide
                        $string9 = /\\PSAsyncShell\.sh/ nocase ascii wide
                        $string10 = /\\PSAsyncShell\-main/ nocase ascii wide
                        $string11 = "c88583cefd0d79a7db5a22290081218d5d9e2ce83de1ca17b8242f7fc74b2535" nocase ascii wide
                        $string12 = "cc49a6056b1f2216c0986cd16b01d2fb5bc03664a2818a5ce3ecdc6a3132707c" nocase ascii wide
                        $string13 = "JoelGMSec/PSAsyncShell" nocase ascii wide
                        $string14 = "PSAsyncShell by @JoelGMSec" nocase ascii wide

    condition:
        any of them
}