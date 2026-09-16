rule rule_NtRemoteLoad_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NtRemoteLoad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtRemoteLoad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NtRemoteLoad_offensive_tool_keyword = /\/HWSyscalls\.cpp/ nocase ascii wide
                        $string2_NtRemoteLoad_offensive_tool_keyword = /\/NtRemoteLoad\.exe/ nocase ascii wide
                        $string3_NtRemoteLoad_offensive_tool_keyword = /\/NtRemoteLoad\.git/ nocase ascii wide
                        $string4_NtRemoteLoad_offensive_tool_keyword = /\\donut\\VanillaProgram\.bin/ nocase ascii wide
                        $string5_NtRemoteLoad_offensive_tool_keyword = /\\HWSyscalls\.cpp/ nocase ascii wide
                        $string6_NtRemoteLoad_offensive_tool_keyword = /\\HWSyscalls\-Example\./ nocase ascii wide
                        $string7_NtRemoteLoad_offensive_tool_keyword = /\\NtRemoteLoad\.exe/ nocase ascii wide
                        $string8_NtRemoteLoad_offensive_tool_keyword = /\\NtRemoteLoad\.sln/ nocase ascii wide
                        $string9_NtRemoteLoad_offensive_tool_keyword = "40B05F26-6A2F-40BC-88DE-F40D4BC77FB0" nocase ascii wide
                        $string10_NtRemoteLoad_offensive_tool_keyword = "florylsk/NtRemoteLoad" nocase ascii wide
                        $string11_NtRemoteLoad_offensive_tool_keyword = "NtRemoteLoad-main" nocase ascii wide

    condition:
        any of them
}