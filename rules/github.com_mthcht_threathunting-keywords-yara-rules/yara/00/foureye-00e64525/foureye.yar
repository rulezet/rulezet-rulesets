rule FourEye
{
    meta:
        description = "Detection patterns for the tool 'FourEye' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FourEye"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sBypassFramework\.py/ nocase ascii wide
                        $string2 = /\sdarkexe\.py/ nocase ascii wide
                        $string3 = /\sUUID_bypass\.py/ nocase ascii wide
                        $string4 = /\/BypassFramework\.py/ nocase ascii wide
                        $string5 = /\/darkexe\.py/ nocase ascii wide
                        $string6 = /\/FourEye\.git/ nocase ascii wide
                        $string7 = "/module/darkexe/" nocase ascii wide
                        $string8 = /\/root\/shellcode\.c/
                        $string9 = /\/root\/shellcode\.cpp/
                        $string10 = /\/root\/shellcode\.exe/
                        $string11 = /\/UUID_bypass\.py/ nocase ascii wide
                        $string12 = /\\darkexe\.py/ nocase ascii wide
                        $string13 = /\\UUID_bypass\.py/ nocase ascii wide
                        $string14 = /FourEye\(shellcode_bypass/ nocase ascii wide
                        $string15 = "FourEye-main" nocase ascii wide
                        $string16 = "lengjibo/FourEye" nocase ascii wide

    condition:
        any of them
}