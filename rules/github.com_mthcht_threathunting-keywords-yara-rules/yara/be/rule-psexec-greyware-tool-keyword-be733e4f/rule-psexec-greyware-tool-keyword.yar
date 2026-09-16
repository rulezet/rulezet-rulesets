rule rule_psexec_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'psexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psexec"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_psexec_greyware_tool_keyword = /\s\-accepteula\s\-nobanner\s\-d\scmd\.exe\s\/c\s/ nocase ascii wide
                        $string2_psexec_greyware_tool_keyword = /\.exe\s\/i\s\/s\scmd\s/ nocase ascii wide
                        $string3_psexec_greyware_tool_keyword = /\.exe\s\/i\s\/s\scmd\.exe/ nocase ascii wide
                        $string4_psexec_greyware_tool_keyword = /\.exe\s\/i\s\/s\spowershell/ nocase ascii wide
                        $string5_psexec_greyware_tool_keyword = /\.exe\s\/i\s\/s\spwsh/ nocase ascii wide
                        $string6_psexec_greyware_tool_keyword = /\.exe\s\/s\s\/i\scmd\.exe/ nocase ascii wide
                        $string7_psexec_greyware_tool_keyword = /\.exe\s\/s\s\/i\spowershell/ nocase ascii wide
                        $string8_psexec_greyware_tool_keyword = /\.exe\s\/s\s\/i\spwsh/ nocase ascii wide
                        $string9_psexec_greyware_tool_keyword = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
                        $string10_psexec_greyware_tool_keyword = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
                        $string11_psexec_greyware_tool_keyword = /\.exe\s\-i\s\-s\scmd\.exe/ nocase ascii wide
                        $string12_psexec_greyware_tool_keyword = /\.exe\s\-i\s\-s\spowershell/ nocase ascii wide
                        $string13_psexec_greyware_tool_keyword = /\.exe\s\-i\s\-s\spwsh/ nocase ascii wide
                        $string14_psexec_greyware_tool_keyword = /\.exe\s\-s\s\-i\scmd\.exe/ nocase ascii wide
                        $string15_psexec_greyware_tool_keyword = /\.exe\s\-s\s\-i\spowershell/ nocase ascii wide
                        $string16_psexec_greyware_tool_keyword = /\.exe\s\-s\s\-i\spwsh/ nocase ascii wide
                        $string17_psexec_greyware_tool_keyword = /\\PsExec\.exe/ nocase ascii wide
                        $string18_psexec_greyware_tool_keyword = /\\SOFTWARE\\Sysinternals\\PsExec\\EulaAccepted/ nocase ascii wide
                        $string19_psexec_greyware_tool_keyword = /\\Windows\\Prefetch\\PSEXEC/ nocase ascii wide
                        $string20_psexec_greyware_tool_keyword = /\\Windows\\PSEXEC\-.{0,1000}\.key/ nocase ascii wide
                        $string21_psexec_greyware_tool_keyword = /PSEXEC\-.{0,1000}\.key/ nocase ascii wide
                        $string22_psexec_greyware_tool_keyword = /PsExec\.exe\s\/accepteula/ nocase ascii wide
                        $string23_psexec_greyware_tool_keyword = /PsExec\[1\]\.exe/ nocase ascii wide
                        $string24_psexec_greyware_tool_keyword = /PsExec64\.exe/ nocase ascii wide
                        $string25_psexec_greyware_tool_keyword = "PSEXECSVC" nocase ascii wide
                        $string26_psexec_greyware_tool_keyword = /PSEXECSVC\.EXE\-.{0,1000}\.pf/ nocase ascii wide

    condition:
        any of them
}