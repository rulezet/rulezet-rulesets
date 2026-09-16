rule NtRemoteLoad
{
    meta:
        description = "Detection patterns for the tool 'NtRemoteLoad' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtRemoteLoad"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HWSyscalls\.cpp/ nocase ascii wide
                        $string2 = /\/NtRemoteLoad\.exe/ nocase ascii wide
                        $string3 = /\/NtRemoteLoad\.git/ nocase ascii wide
                        $string4 = /\\donut\\VanillaProgram\.bin/ nocase ascii wide
                        $string5 = /\\HWSyscalls\.cpp/ nocase ascii wide
                        $string6 = /\\HWSyscalls\-Example\./ nocase ascii wide
                        $string7 = /\\NtRemoteLoad\.exe/ nocase ascii wide
                        $string8 = /\\NtRemoteLoad\.sln/ nocase ascii wide
                        $string9 = "40B05F26-6A2F-40BC-88DE-F40D4BC77FB0" nocase ascii wide
                        $string10 = "florylsk/NtRemoteLoad" nocase ascii wide
                        $string11 = "NtRemoteLoad-main" nocase ascii wide

    condition:
        any of them
}