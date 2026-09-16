rule rule_dploot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dploot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dploot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dploot_offensive_tool_keyword = " -m rdrleakdiag -M masterkeys" nocase ascii wide
                        $string2_dploot_offensive_tool_keyword = /\/dploot\.git/ nocase ascii wide
                        $string3_dploot_offensive_tool_keyword = /\]\sTriage\sSCCM\sSecrets/ nocase ascii wide
                        $string4_dploot_offensive_tool_keyword = /decrypt_chrome_password\(/ nocase ascii wide
                        $string5_dploot_offensive_tool_keyword = "dploot -" nocase ascii wide
                        $string6_dploot_offensive_tool_keyword = "dploot sccm -d" nocase ascii wide
                        $string7_dploot_offensive_tool_keyword = /dploot.{0,1000}backupkey/ nocase ascii wide
                        $string8_dploot_offensive_tool_keyword = /dploot.{0,1000}browser/ nocase ascii wide
                        $string9_dploot_offensive_tool_keyword = /dploot.{0,1000}certificates/ nocase ascii wide
                        $string10_dploot_offensive_tool_keyword = /dploot.{0,1000}credentials/ nocase ascii wide
                        $string11_dploot_offensive_tool_keyword = /dploot.{0,1000}machinecertificates/ nocase ascii wide
                        $string12_dploot_offensive_tool_keyword = /dploot.{0,1000}machinecredentials/ nocase ascii wide
                        $string13_dploot_offensive_tool_keyword = /dploot.{0,1000}machinemasterkeys/ nocase ascii wide
                        $string14_dploot_offensive_tool_keyword = /dploot.{0,1000}machinevaults/ nocase ascii wide
                        $string15_dploot_offensive_tool_keyword = /dploot.{0,1000}masterkeys/ nocase ascii wide
                        $string16_dploot_offensive_tool_keyword = /dploot.{0,1000}vaults/ nocase ascii wide
                        $string17_dploot_offensive_tool_keyword = /dploot.{0,1000}wifi/ nocase ascii wide
                        $string18_dploot_offensive_tool_keyword = /dploot\.lib\.dpapi/ nocase ascii wide
                        $string19_dploot_offensive_tool_keyword = /dploot\.lib\.smb/ nocase ascii wide
                        $string20_dploot_offensive_tool_keyword = /dploot\.triage\./ nocase ascii wide
                        $string21_dploot_offensive_tool_keyword = /dploot\.triage\.sccm\simport\sSCCMTriage/ nocase ascii wide
                        $string22_dploot_offensive_tool_keyword = /dploot\/releases\/download\/.{0,1000}\/dploot/ nocase ascii wide
                        $string23_dploot_offensive_tool_keyword = "dploot_linux_adm64"
                        $string24_dploot_offensive_tool_keyword = /dploot\-main\.zip/ nocase ascii wide
                        $string25_dploot_offensive_tool_keyword = "Dump looted SCCM secrets to specified directory" nocase ascii wide
                        $string26_dploot_offensive_tool_keyword = "Dump SCCM secrets from WMI requests results" nocase ascii wide
                        $string27_dploot_offensive_tool_keyword = "import DPLootSMBConnection" nocase ascii wide
                        $string28_dploot_offensive_tool_keyword = "install dploot" nocase ascii wide
                        $string29_dploot_offensive_tool_keyword = "lsassy -" nocase ascii wide
                        $string30_dploot_offensive_tool_keyword = "Password:Waza1234" nocase ascii wide
                        $string31_dploot_offensive_tool_keyword = "zblurx/dploot" nocase ascii wide

    condition:
        any of them
}