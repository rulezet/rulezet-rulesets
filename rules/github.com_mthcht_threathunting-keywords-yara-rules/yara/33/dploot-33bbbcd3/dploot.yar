rule dploot
{
    meta:
        description = "Detection patterns for the tool 'dploot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dploot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -m rdrleakdiag -M masterkeys" nocase ascii wide
                        $string2 = /\/dploot\.git/ nocase ascii wide
                        $string3 = /\]\sTriage\sSCCM\sSecrets/ nocase ascii wide
                        $string4 = /decrypt_chrome_password\(/ nocase ascii wide
                        $string5 = "dploot -" nocase ascii wide
                        $string6 = "dploot sccm -d" nocase ascii wide
                        $string7 = /dploot.{0,1000}backupkey/ nocase ascii wide
                        $string8 = /dploot.{0,1000}browser/ nocase ascii wide
                        $string9 = /dploot.{0,1000}certificates/ nocase ascii wide
                        $string10 = /dploot.{0,1000}credentials/ nocase ascii wide
                        $string11 = /dploot.{0,1000}machinecertificates/ nocase ascii wide
                        $string12 = /dploot.{0,1000}machinecredentials/ nocase ascii wide
                        $string13 = /dploot.{0,1000}machinemasterkeys/ nocase ascii wide
                        $string14 = /dploot.{0,1000}machinevaults/ nocase ascii wide
                        $string15 = /dploot.{0,1000}masterkeys/ nocase ascii wide
                        $string16 = /dploot.{0,1000}vaults/ nocase ascii wide
                        $string17 = /dploot.{0,1000}wifi/ nocase ascii wide
                        $string18 = /dploot\.lib\.dpapi/ nocase ascii wide
                        $string19 = /dploot\.lib\.smb/ nocase ascii wide
                        $string20 = /dploot\.triage\./ nocase ascii wide
                        $string21 = /dploot\.triage\.sccm\simport\sSCCMTriage/ nocase ascii wide
                        $string22 = /dploot\/releases\/download\/.{0,1000}\/dploot/ nocase ascii wide
                        $string23 = "dploot_linux_adm64"
                        $string24 = /dploot\-main\.zip/ nocase ascii wide
                        $string25 = "Dump looted SCCM secrets to specified directory" nocase ascii wide
                        $string26 = "Dump SCCM secrets from WMI requests results" nocase ascii wide
                        $string27 = "import DPLootSMBConnection" nocase ascii wide
                        $string28 = "install dploot" nocase ascii wide
                        $string29 = "lsassy -" nocase ascii wide
                        $string30 = "Password:Waza1234" nocase ascii wide
                        $string31 = "zblurx/dploot" nocase ascii wide

    condition:
        any of them
}