rule rule_OffensiveLua_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OffensiveLua' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveLua"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OffensiveLua_offensive_tool_keyword = /\sc\:\\\\Temp\\\\lua\.log/ nocase ascii wide
                        $string2_OffensiveLua_offensive_tool_keyword = /\/bin2hex\.lua/ nocase ascii wide
                        $string3_OffensiveLua_offensive_tool_keyword = /\/bindshell\.lua/ nocase ascii wide
                        $string4_OffensiveLua_offensive_tool_keyword = /\/downloadexec\.lua/ nocase ascii wide
                        $string5_OffensiveLua_offensive_tool_keyword = /\/OffensiveLua\.git/ nocase ascii wide
                        $string6_OffensiveLua_offensive_tool_keyword = /\/regread\.lua/ nocase ascii wide
                        $string7_OffensiveLua_offensive_tool_keyword = /\/regwrite\.lua/ nocase ascii wide
                        $string8_OffensiveLua_offensive_tool_keyword = /\/regwritedel\.lua/ nocase ascii wide
                        $string9_OffensiveLua_offensive_tool_keyword = /\/runcmd\.lua/ nocase ascii wide
                        $string10_OffensiveLua_offensive_tool_keyword = /\/runcmd2\.lua/ nocase ascii wide
                        $string11_OffensiveLua_offensive_tool_keyword = /\/runswhide\.lua/ nocase ascii wide
                        $string12_OffensiveLua_offensive_tool_keyword = /\\\\Users\\\\Fantastic\\\\Desktop\\\\DEMO\\\\plugins\\\\scripts\\\\/ nocase ascii wide
                        $string13_OffensiveLua_offensive_tool_keyword = /\\bin2hex\.lua/ nocase ascii wide
                        $string14_OffensiveLua_offensive_tool_keyword = /\\bindshell\.lua/ nocase ascii wide
                        $string15_OffensiveLua_offensive_tool_keyword = /\\downloadexec\.lua/ nocase ascii wide
                        $string16_OffensiveLua_offensive_tool_keyword = /\\luajit\.exe/ nocase ascii wide
                        $string17_OffensiveLua_offensive_tool_keyword = /\\regread\.lua/ nocase ascii wide
                        $string18_OffensiveLua_offensive_tool_keyword = /\\regwrite\.lua/ nocase ascii wide
                        $string19_OffensiveLua_offensive_tool_keyword = /\\regwritedel\.lua/ nocase ascii wide
                        $string20_OffensiveLua_offensive_tool_keyword = /\\runcmd\.lua/ nocase ascii wide
                        $string21_OffensiveLua_offensive_tool_keyword = /\\runcmd2\.lua/ nocase ascii wide
                        $string22_OffensiveLua_offensive_tool_keyword = /\\runswhide\.lua/ nocase ascii wide
                        $string23_OffensiveLua_offensive_tool_keyword = /\\x4d\\x5a\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff\\x00\\x00\\xb8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xf8\\x00\\x00\\x00\\x0e\\x1f\\xba\\x0e\\x00\\xb4\\x09\\xcd\\x21\\xb8\\x01\\x4c\\xcd\\x21\\x54\\x68\\x69\\x73\\x20\\x70\\x72/ nocase ascii wide
                        $string24_OffensiveLua_offensive_tool_keyword = /C\:\\\\temp\\\\test\.txt/ nocase ascii wide
                        $string25_OffensiveLua_offensive_tool_keyword = /ComputerDefaultsUACBypass\.lua/ nocase ascii wide
                        $string26_OffensiveLua_offensive_tool_keyword = /copy\sTsutsuji_x64\.dll\s\%appdata\%.{0,1000}Local\\Microsoft\\WindowsApps\\BluetoothDiagnosticUtil\.dll/ nocase ascii wide
                        $string27_OffensiveLua_offensive_tool_keyword = /downloadexec_UACbypass\.lua/ nocase ascii wide
                        $string28_OffensiveLua_offensive_tool_keyword = "hackerhouse-opensource/OffensiveLua" nocase ascii wide
                        $string29_OffensiveLua_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/Renge_x64\.exe/ nocase ascii wide
                        $string30_OffensiveLua_offensive_tool_keyword = "OffensiveLua-main" nocase ascii wide
                        $string31_OffensiveLua_offensive_tool_keyword = /uac_bypass_bluetooth_win10\.lua/ nocase ascii wide

    condition:
        any of them
}