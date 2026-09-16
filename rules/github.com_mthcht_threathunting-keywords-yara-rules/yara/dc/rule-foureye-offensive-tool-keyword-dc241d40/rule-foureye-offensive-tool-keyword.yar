rule rule_FourEye_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FourEye' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FourEye"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_FourEye_offensive_tool_keyword = /\sBypassFramework\.py/ nocase ascii wide
                        $string2_FourEye_offensive_tool_keyword = /\sdarkexe\.py/ nocase ascii wide
                        $string3_FourEye_offensive_tool_keyword = /\sUUID_bypass\.py/ nocase ascii wide
                        $string4_FourEye_offensive_tool_keyword = /\/BypassFramework\.py/ nocase ascii wide
                        $string5_FourEye_offensive_tool_keyword = /\/darkexe\.py/ nocase ascii wide
                        $string6_FourEye_offensive_tool_keyword = /\/FourEye\.git/ nocase ascii wide
                        $string7_FourEye_offensive_tool_keyword = "/module/darkexe/" nocase ascii wide
                        $string8_FourEye_offensive_tool_keyword = /\/root\/shellcode\.c/
                        $string9_FourEye_offensive_tool_keyword = /\/root\/shellcode\.cpp/
                        $string10_FourEye_offensive_tool_keyword = /\/root\/shellcode\.exe/
                        $string11_FourEye_offensive_tool_keyword = /\/UUID_bypass\.py/ nocase ascii wide
                        $string12_FourEye_offensive_tool_keyword = /\\darkexe\.py/ nocase ascii wide
                        $string13_FourEye_offensive_tool_keyword = /\\UUID_bypass\.py/ nocase ascii wide
                        $string14_FourEye_offensive_tool_keyword = /FourEye\(shellcode_bypass/ nocase ascii wide
                        $string15_FourEye_offensive_tool_keyword = "FourEye-main" nocase ascii wide
                        $string16_FourEye_offensive_tool_keyword = "lengjibo/FourEye" nocase ascii wide

    condition:
        any of them
}