rule rule_NativeDump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NativeDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NativeDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NativeDump_offensive_tool_keyword = /\sNativeDump\.exe/ nocase ascii wide
                        $string2_NativeDump_offensive_tool_keyword = /\/Lsass_Shtinkering\.cpp/ nocase ascii wide
                        $string3_NativeDump_offensive_tool_keyword = /\/Lsass_Shtinkering\.exe/ nocase ascii wide
                        $string4_NativeDump_offensive_tool_keyword = /\/Lsass\-Shtinkering\.git/ nocase ascii wide
                        $string5_NativeDump_offensive_tool_keyword = /\/NativeDump\.exe/ nocase ascii wide
                        $string6_NativeDump_offensive_tool_keyword = /\/NativeDump\.git/ nocase ascii wide
                        $string7_NativeDump_offensive_tool_keyword = /\\Lsass_Shtinkering\.cpp/ nocase ascii wide
                        $string8_NativeDump_offensive_tool_keyword = /\\LSASS_Shtinkering\.sln/ nocase ascii wide
                        $string9_NativeDump_offensive_tool_keyword = /\\LSASS_Shtinkering\\/ nocase ascii wide
                        $string10_NativeDump_offensive_tool_keyword = /\\Lsass\-Shtinkering\-main/ nocase ascii wide
                        $string11_NativeDump_offensive_tool_keyword = /\\NativeDump\.csproj/ nocase ascii wide
                        $string12_NativeDump_offensive_tool_keyword = /\\NativeDump\.exe/ nocase ascii wide
                        $string13_NativeDump_offensive_tool_keyword = /\\NativeDump\.sln/ nocase ascii wide
                        $string14_NativeDump_offensive_tool_keyword = /\\NativeDump\\Program\.cs/ nocase ascii wide
                        $string15_NativeDump_offensive_tool_keyword = "0DF612AE-47D8-422C-B0C5-0727EA60784F" nocase ascii wide
                        $string16_NativeDump_offensive_tool_keyword = "254389e27339fd66920dd72f3ad07fe2e220f6b0cbea8032cf0b1d8285a7b098" nocase ascii wide
                        $string17_NativeDump_offensive_tool_keyword = "476FC126-239F-4D58-8389-E1C0E93C2C5E" nocase ascii wide
                        $string18_NativeDump_offensive_tool_keyword = "5571bc0232f7f7911042503b2a2224ad420788d999eb819257a00943928a56bb" nocase ascii wide
                        $string19_NativeDump_offensive_tool_keyword = "5ccafa7f7b00774dd423a64460ef3d1c551ee95f076107cb8353f6271819f4d7" nocase ascii wide
                        $string20_NativeDump_offensive_tool_keyword = "9b7e60f60ab5e2680554d392c3e8a84b9e367a6e452eaab011d1eef963aad894" nocase ascii wide
                        $string21_NativeDump_offensive_tool_keyword = "deepinstinct/Lsass-Shtinkering" nocase ascii wide
                        $string22_NativeDump_offensive_tool_keyword = "ef9c57ffe31d8ceeb51daeac466dc8835807ab7d9fd3ff05ada8ce9b4836d924" nocase ascii wide
                        $string23_NativeDump_offensive_tool_keyword = /NativeDump\.exe\s.{0,1000}\.dmp/ nocase ascii wide
                        $string24_NativeDump_offensive_tool_keyword = /process\smust\srun\sas\sNT\sAUTHORITY\\\\SYSTEM\sto\sdump\slsass\smemory/ nocase ascii wide
                        $string25_NativeDump_offensive_tool_keyword = "ricardojoserf/NativeDump" nocase ascii wide

    condition:
        any of them
}