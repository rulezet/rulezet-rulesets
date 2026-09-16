rule OffensiveLua
{
    meta:
        description = "Detection patterns for the tool 'OffensiveLua' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveLua"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sc\:\\\\Temp\\\\lua\.log/ nocase ascii wide
                        $string2 = /\/bin2hex\.lua/ nocase ascii wide
                        $string3 = /\/bindshell\.lua/ nocase ascii wide
                        $string4 = /\/downloadexec\.lua/ nocase ascii wide
                        $string5 = /\/OffensiveLua\.git/ nocase ascii wide
                        $string6 = /\/regread\.lua/ nocase ascii wide
                        $string7 = /\/regwrite\.lua/ nocase ascii wide
                        $string8 = /\/regwritedel\.lua/ nocase ascii wide
                        $string9 = /\/runcmd\.lua/ nocase ascii wide
                        $string10 = /\/runcmd2\.lua/ nocase ascii wide
                        $string11 = /\/runswhide\.lua/ nocase ascii wide
                        $string12 = /\\\\Users\\\\Fantastic\\\\Desktop\\\\DEMO\\\\plugins\\\\scripts\\\\/ nocase ascii wide
                        $string13 = /\\bin2hex\.lua/ nocase ascii wide
                        $string14 = /\\bindshell\.lua/ nocase ascii wide
                        $string15 = /\\downloadexec\.lua/ nocase ascii wide
                        $string16 = /\\luajit\.exe/ nocase ascii wide
                        $string17 = /\\regread\.lua/ nocase ascii wide
                        $string18 = /\\regwrite\.lua/ nocase ascii wide
                        $string19 = /\\regwritedel\.lua/ nocase ascii wide
                        $string20 = /\\runcmd\.lua/ nocase ascii wide
                        $string21 = /\\runcmd2\.lua/ nocase ascii wide
                        $string22 = /\\runswhide\.lua/ nocase ascii wide
                        $string23 = /\\x4d\\x5a\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff\\x00\\x00\\xb8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xf8\\x00\\x00\\x00\\x0e\\x1f\\xba\\x0e\\x00\\xb4\\x09\\xcd\\x21\\xb8\\x01\\x4c\\xcd\\x21\\x54\\x68\\x69\\x73\\x20\\x70\\x72/ nocase ascii wide
                        $string24 = /C\:\\\\temp\\\\test\.txt/ nocase ascii wide
                        $string25 = /ComputerDefaultsUACBypass\.lua/ nocase ascii wide
                        $string26 = /copy\sTsutsuji_x64\.dll\s\%appdata\%.{0,1000}Local\\Microsoft\\WindowsApps\\BluetoothDiagnosticUtil\.dll/ nocase ascii wide
                        $string27 = /downloadexec_UACbypass\.lua/ nocase ascii wide
                        $string28 = "hackerhouse-opensource/OffensiveLua" nocase ascii wide
                        $string29 = /http\:\/\/127\.0\.0\.1\/Renge_x64\.exe/ nocase ascii wide
                        $string30 = "OffensiveLua-main" nocase ascii wide
                        $string31 = /uac_bypass_bluetooth_win10\.lua/ nocase ascii wide

    condition:
        any of them
}