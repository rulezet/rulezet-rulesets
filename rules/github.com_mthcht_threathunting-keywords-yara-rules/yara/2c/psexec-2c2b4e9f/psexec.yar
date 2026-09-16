rule psexec
{
    meta:
        description = "Detection patterns for the tool 'psexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psexec"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-accepteula\s\-nobanner\s\-d\scmd\.exe\s\/c\s/ nocase ascii wide
                        $string2 = /\.exe\s\/i\s\/s\scmd\s/ nocase ascii wide
                        $string3 = /\.exe\s\/i\s\/s\scmd\.exe/ nocase ascii wide
                        $string4 = /\.exe\s\/i\s\/s\spowershell/ nocase ascii wide
                        $string5 = /\.exe\s\/i\s\/s\spwsh/ nocase ascii wide
                        $string6 = /\.exe\s\/s\s\/i\scmd\.exe/ nocase ascii wide
                        $string7 = /\.exe\s\/s\s\/i\spowershell/ nocase ascii wide
                        $string8 = /\.exe\s\/s\s\/i\spwsh/ nocase ascii wide
                        $string9 = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
                        $string10 = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
                        $string11 = /\.exe\s\-i\s\-s\scmd\.exe/ nocase ascii wide
                        $string12 = /\.exe\s\-i\s\-s\spowershell/ nocase ascii wide
                        $string13 = /\.exe\s\-i\s\-s\spwsh/ nocase ascii wide
                        $string14 = /\.exe\s\-s\s\-i\scmd\.exe/ nocase ascii wide
                        $string15 = /\.exe\s\-s\s\-i\spowershell/ nocase ascii wide
                        $string16 = /\.exe\s\-s\s\-i\spwsh/ nocase ascii wide
                        $string17 = /\\PsExec\.exe/ nocase ascii wide
                        $string18 = /\\SOFTWARE\\Sysinternals\\PsExec\\EulaAccepted/ nocase ascii wide
                        $string19 = /\\Windows\\Prefetch\\PSEXEC/ nocase ascii wide
                        $string20 = /\\Windows\\PSEXEC\-.{0,1000}\.key/ nocase ascii wide
                        $string21 = /PSEXEC\-.{0,1000}\.key/ nocase ascii wide
                        $string22 = /PsExec\.exe\s\/accepteula/ nocase ascii wide
                        $string23 = /PsExec\[1\]\.exe/ nocase ascii wide
                        $string24 = /PsExec64\.exe/ nocase ascii wide
                        $string25 = "PSEXECSVC" nocase ascii wide
                        $string26 = /PSEXECSVC\.EXE\-.{0,1000}\.pf/ nocase ascii wide

    condition:
        any of them
}