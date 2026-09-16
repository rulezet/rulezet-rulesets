rule rule_PSAsyncShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSAsyncShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAsyncShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSAsyncShell_offensive_tool_keyword = /\sPSAsyncShell\.ps1/ nocase ascii wide
                        $string2_PSAsyncShell_offensive_tool_keyword = /\sPSAsyncShell\.sh/ nocase ascii wide
                        $string3_PSAsyncShell_offensive_tool_keyword = /\/PSAsyncShell\.git/ nocase ascii wide
                        $string4_PSAsyncShell_offensive_tool_keyword = /\/PSAsyncShell\.ps1/ nocase ascii wide
                        $string5_PSAsyncShell_offensive_tool_keyword = /\/PSAsyncShell\.sh/ nocase ascii wide
                        $string6_PSAsyncShell_offensive_tool_keyword = "/PSAsyncShell-main" nocase ascii wide
                        $string7_PSAsyncShell_offensive_tool_keyword = /\[\+\]\sPSAsyncShell\sOK\!/ nocase ascii wide
                        $string8_PSAsyncShell_offensive_tool_keyword = /\\PSAsyncShell\.ps1/ nocase ascii wide
                        $string9_PSAsyncShell_offensive_tool_keyword = /\\PSAsyncShell\.sh/ nocase ascii wide
                        $string10_PSAsyncShell_offensive_tool_keyword = /\\PSAsyncShell\-main/ nocase ascii wide
                        $string11_PSAsyncShell_offensive_tool_keyword = "c88583cefd0d79a7db5a22290081218d5d9e2ce83de1ca17b8242f7fc74b2535" nocase ascii wide
                        $string12_PSAsyncShell_offensive_tool_keyword = "cc49a6056b1f2216c0986cd16b01d2fb5bc03664a2818a5ce3ecdc6a3132707c" nocase ascii wide
                        $string13_PSAsyncShell_offensive_tool_keyword = "JoelGMSec/PSAsyncShell" nocase ascii wide
                        $string14_PSAsyncShell_offensive_tool_keyword = "PSAsyncShell by @JoelGMSec" nocase ascii wide

    condition:
        any of them
}