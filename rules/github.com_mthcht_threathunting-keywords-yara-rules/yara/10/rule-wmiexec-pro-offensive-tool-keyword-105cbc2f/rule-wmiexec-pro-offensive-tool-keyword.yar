rule rule_wmiexec_pro_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wmiexec-pro' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec-pro"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wmiexec_pro_offensive_tool_keyword = " exec-command -clear" nocase ascii wide
                        $string2_wmiexec_pro_offensive_tool_keyword = " exec-command -command " nocase ascii wide
                        $string3_wmiexec_pro_offensive_tool_keyword = " exec-command -shell" nocase ascii wide
                        $string4_wmiexec_pro_offensive_tool_keyword = /\sfiletransfer\s\-download\s\-src\-file\s.{0,1000}\.exe.{0,1000}\/tmp/ nocase ascii wide
                        $string5_wmiexec_pro_offensive_tool_keyword = /\sfiletransfer\s\-upload\s\-src\-file\s.{0,1000}\.exe.{0,1000}\\temp/ nocase ascii wide
                        $string6_wmiexec_pro_offensive_tool_keyword = " -no-pass rid-hijack" nocase ascii wide
                        $string7_wmiexec_pro_offensive_tool_keyword = " rid-hijack -" nocase ascii wide
                        $string8_wmiexec_pro_offensive_tool_keyword = /\sservice\s\-dump\sall\-services\.json/ nocase ascii wide
                        $string9_wmiexec_pro_offensive_tool_keyword = /\.py\s.{0,1000}\samsi\s\-disable/ nocase ascii wide
                        $string10_wmiexec_pro_offensive_tool_keyword = /\.py\s.{0,1000}\samsi\s\-enable/ nocase ascii wide
                        $string11_wmiexec_pro_offensive_tool_keyword = /\.py.{0,1000}\sservice\s\-action\screate\s\-service\-name\s/ nocase ascii wide
                        $string12_wmiexec_pro_offensive_tool_keyword = "/wmiexec-Pro" nocase ascii wide
                        $string13_wmiexec_pro_offensive_tool_keyword = /\/wmiexec\-Pro\.git/ nocase ascii wide
                        $string14_wmiexec_pro_offensive_tool_keyword = /\[\+\]\sAMSI\sBypassed\!/ nocase ascii wide
                        $string15_wmiexec_pro_offensive_tool_keyword = /\[\+\]\sCreate\sevil\sclass\sfor\sfile\stransfer/ nocase ascii wide
                        $string16_wmiexec_pro_offensive_tool_keyword = /\[\+\]\sNuke\sis\slanding\./ nocase ascii wide
                        $string17_wmiexec_pro_offensive_tool_keyword = /\\filetransfer\.py/ nocase ascii wide
                        $string18_wmiexec_pro_offensive_tool_keyword = /\\rid_hijack\.py/ nocase ascii wide
                        $string19_wmiexec_pro_offensive_tool_keyword = "53395d8379dfd716e8708b21490fdec662537be8c56d0df185df59d0ed68eb04" nocase ascii wide
                        $string20_wmiexec_pro_offensive_tool_keyword = "8bce6c99c0ac4b8d76c49f6e4dece996b77bb7d71d9acdbfcf5b0460811adfb9" nocase ascii wide
                        $string21_wmiexec_pro_offensive_tool_keyword = "bfe2e4b99edec9921d20bc7f956c1ac48cfc0b08061e23c92ab3461d7cdcf922" nocase ascii wide
                        $string22_wmiexec_pro_offensive_tool_keyword = /C\:\\aab\.txt/ nocase ascii wide
                        $string23_wmiexec_pro_offensive_tool_keyword = /ClearEventlog\.vbs/ nocase ascii wide
                        $string24_wmiexec_pro_offensive_tool_keyword = /ClearEventlog\.vbs/ nocase ascii wide
                        $string25_wmiexec_pro_offensive_tool_keyword = "e6db508c611d834b9ad9f20bebef8507fec5f642a051ea1c6ae659b729db3c1c" nocase ascii wide
                        $string26_wmiexec_pro_offensive_tool_keyword = "eventlog -risk-i-know" nocase ascii wide
                        $string27_wmiexec_pro_offensive_tool_keyword = /eventlog_fucker\.py/ nocase ascii wide
                        $string28_wmiexec_pro_offensive_tool_keyword = /eventlog\-fucker\.py/ nocase ascii wide
                        $string29_wmiexec_pro_offensive_tool_keyword = /Exec\-Command\-Silent\.vbs/ nocase ascii wide
                        $string30_wmiexec_pro_offensive_tool_keyword = /Exec\-Command\-Silent\.vbs/ nocase ascii wide
                        $string31_wmiexec_pro_offensive_tool_keyword = /GrantSamAccessPermission\.vbs/ nocase ascii wide
                        $string32_wmiexec_pro_offensive_tool_keyword = /GrantSamAccessPermission\.vbs/ nocase ascii wide
                        $string33_wmiexec_pro_offensive_tool_keyword = /modules\/enumrate\.py/ nocase ascii wide
                        $string34_wmiexec_pro_offensive_tool_keyword = /rid_hijack\.py/ nocase ascii wide
                        $string35_wmiexec_pro_offensive_tool_keyword = /wmiexec\-Pro\.git/ nocase ascii wide
                        $string36_wmiexec_pro_offensive_tool_keyword = /wmiexec\-pro\.py/ nocase ascii wide
                        $string37_wmiexec_pro_offensive_tool_keyword = "wmiexec-Pro/tarball" nocase ascii wide
                        $string38_wmiexec_pro_offensive_tool_keyword = "wmiexec-Pro/zipball" nocase ascii wide
                        $string39_wmiexec_pro_offensive_tool_keyword = /wmipersist\.py/ nocase ascii wide
                        $string40_wmiexec_pro_offensive_tool_keyword = "XiaoliChan/wmiexec-Pro" nocase ascii wide

    condition:
        any of them
}