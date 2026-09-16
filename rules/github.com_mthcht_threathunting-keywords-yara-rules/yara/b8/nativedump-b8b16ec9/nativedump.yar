rule NativeDump
{
    meta:
        description = "Detection patterns for the tool 'NativeDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NativeDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sNativeDump\.exe/ nocase ascii wide
                        $string2 = /\/Lsass_Shtinkering\.cpp/ nocase ascii wide
                        $string3 = /\/Lsass_Shtinkering\.exe/ nocase ascii wide
                        $string4 = /\/Lsass\-Shtinkering\.git/ nocase ascii wide
                        $string5 = /\/NativeDump\.exe/ nocase ascii wide
                        $string6 = /\/NativeDump\.git/ nocase ascii wide
                        $string7 = /\\Lsass_Shtinkering\.cpp/ nocase ascii wide
                        $string8 = /\\LSASS_Shtinkering\.sln/ nocase ascii wide
                        $string9 = /\\LSASS_Shtinkering\\/ nocase ascii wide
                        $string10 = /\\Lsass\-Shtinkering\-main/ nocase ascii wide
                        $string11 = /\\NativeDump\.csproj/ nocase ascii wide
                        $string12 = /\\NativeDump\.exe/ nocase ascii wide
                        $string13 = /\\NativeDump\.sln/ nocase ascii wide
                        $string14 = /\\NativeDump\\Program\.cs/ nocase ascii wide
                        $string15 = "0DF612AE-47D8-422C-B0C5-0727EA60784F" nocase ascii wide
                        $string16 = "254389e27339fd66920dd72f3ad07fe2e220f6b0cbea8032cf0b1d8285a7b098" nocase ascii wide
                        $string17 = "476FC126-239F-4D58-8389-E1C0E93C2C5E" nocase ascii wide
                        $string18 = "5571bc0232f7f7911042503b2a2224ad420788d999eb819257a00943928a56bb" nocase ascii wide
                        $string19 = "5ccafa7f7b00774dd423a64460ef3d1c551ee95f076107cb8353f6271819f4d7" nocase ascii wide
                        $string20 = "9b7e60f60ab5e2680554d392c3e8a84b9e367a6e452eaab011d1eef963aad894" nocase ascii wide
                        $string21 = "deepinstinct/Lsass-Shtinkering" nocase ascii wide
                        $string22 = "ef9c57ffe31d8ceeb51daeac466dc8835807ab7d9fd3ff05ada8ce9b4836d924" nocase ascii wide
                        $string23 = /NativeDump\.exe\s.{0,1000}\.dmp/ nocase ascii wide
                        $string24 = /process\smust\srun\sas\sNT\sAUTHORITY\\\\SYSTEM\sto\sdump\slsass\smemory/ nocase ascii wide
                        $string25 = "ricardojoserf/NativeDump" nocase ascii wide

    condition:
        any of them
}