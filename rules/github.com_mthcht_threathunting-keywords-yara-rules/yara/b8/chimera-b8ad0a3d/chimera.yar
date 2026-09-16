rule chimera
{
    meta:
        description = "Detection patterns for the tool 'chimera' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chimera"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\schimera\.sh/ nocase ascii wide
                        $string2 = /\s\-f\s.{0,1000}\.ps1\s\-l\s3\s\-o\s.{0,1000}\.ps1\s\-v\s\-t\spowershell.{0,1000}reverse/ nocase ascii wide
                        $string3 = /\s\-f\sshells\/generic1\.ps1\s/ nocase ascii wide
                        $string4 = /\s\-s\s.{0,1000}ascii.{0,1000}\s\-b\s.{0,1000}reverse.{0,1000}invoke\-expression/ nocase ascii wide
                        $string5 = /\/Chimera\.git/ nocase ascii wide
                        $string6 = /\/chimera\.sh/ nocase ascii wide
                        $string7 = "/opt/chimera"
                        $string8 = /\/tmp\/chimera\.ps1/
                        $string9 = /\/tmp\/payload\.ps1/
                        $string10 = /\/tmp\/vt\-post\-.{0,1000}\.txt/
                        $string11 = /\/tmp\/vt\-results\-.{0,1000}\.txt/
                        $string12 = /Add\-RegBackdoor\.ps1/ nocase ascii wide
                        $string13 = /Chimera\-master\.zip/ nocase ascii wide
                        $string14 = /Get\-WLAN\-Keys\.ps1/ nocase ascii wide
                        $string15 = "Invoke-PortScan" nocase ascii wide
                        $string16 = "Invoke-PoshRatHttp" nocase ascii wide
                        $string17 = /Invoke\-PowerShellIcmp\.ps1/ nocase ascii wide
                        $string18 = /Invoke\-PowerShellTcp\.ps1/ nocase ascii wide
                        $string19 = /Invoke\-PowerShellTcpOneLine\.ps1/ nocase ascii wide
                        $string20 = /Invoke\-PowerShellUdp\.ps1/ nocase ascii wide
                        $string21 = /Invoke\-PowerShellUdpOneLine\.ps1/ nocase ascii wide
                        $string22 = /null\-byte\.com\/bypass\-amsi/ nocase ascii wide
                        $string23 = /powershell_reverse_shell\.ps1/ nocase ascii wide
                        $string24 = "tokyoneon/Chimera" nocase ascii wide

    condition:
        any of them
}