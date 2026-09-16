rule rule_SharPersist_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharPersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharPersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharPersist_offensive_tool_keyword = " keepass backdoor persistence" nocase ascii wide
                        $string2_SharPersist_offensive_tool_keyword = " Keepass persistence backdoor " nocase ascii wide
                        $string3_SharPersist_offensive_tool_keyword = " -t schtaskbackdoor " nocase ascii wide
                        $string4_SharPersist_offensive_tool_keyword = /\.exe\s\-t\skeepass\s\-f\s/ nocase ascii wide
                        $string5_SharPersist_offensive_tool_keyword = /\.exe\s\-t\sstartupfolder\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-f/ nocase ascii wide
                        $string6_SharPersist_offensive_tool_keyword = /\.exe\s\-t\stortoisesvn\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-m/ nocase ascii wide
                        $string7_SharPersist_offensive_tool_keyword = /\/SharPersist\.git/ nocase ascii wide
                        $string8_SharPersist_offensive_tool_keyword = /\\SchTaskBackdoor\./ nocase ascii wide
                        $string9_SharPersist_offensive_tool_keyword = /\\SharPersist\\/ nocase ascii wide
                        $string10_SharPersist_offensive_tool_keyword = /\\TortoiseSVNHookScripts\.cs/ nocase ascii wide
                        $string11_SharPersist_offensive_tool_keyword = "7806b81514ecc44219a6f6193b15b23aea0a947f3c91b339332bea1445745596" nocase ascii wide
                        $string12_SharPersist_offensive_tool_keyword = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" nocase ascii wide
                        $string13_SharPersist_offensive_tool_keyword = /c\:\\123\.txt/ nocase ascii wide
                        $string14_SharPersist_offensive_tool_keyword = "e9711f47cf9171f79bf34b342279f6fd9275c8ae65f3eb2c6ebb0b8432ea14f8" nocase ascii wide
                        $string15_SharPersist_offensive_tool_keyword = "INFO: Adding keepass backdoor persistence" nocase ascii wide
                        $string16_SharPersist_offensive_tool_keyword = "INFO: Adding registry persistence" nocase ascii wide
                        $string17_SharPersist_offensive_tool_keyword = "INFO: Adding scheduled task backdoor persistence" nocase ascii wide
                        $string18_SharPersist_offensive_tool_keyword = "INFO: Adding scheduled task persistence" nocase ascii wide
                        $string19_SharPersist_offensive_tool_keyword = "INFO: Adding service persistence" nocase ascii wide
                        $string20_SharPersist_offensive_tool_keyword = "INFO: Adding startup folder persistence" nocase ascii wide
                        $string21_SharPersist_offensive_tool_keyword = "INFO: Adding tortoise svn persistence" nocase ascii wide
                        $string22_SharPersist_offensive_tool_keyword = "INFO: Checking backdoor present in KeePass config file" nocase ascii wide
                        $string23_SharPersist_offensive_tool_keyword = /INFO\:\sListing\sall\sscheduled\stasks\savailable\sto\sbackdoor\./ nocase ascii wide
                        $string24_SharPersist_offensive_tool_keyword = "KeePass config file is backdoored already" nocase ascii wide
                        $string25_SharPersist_offensive_tool_keyword = /KeePassBackdoor\./ nocase ascii wide
                        $string26_SharPersist_offensive_tool_keyword = "mandiant/SharPersist" nocase ascii wide
                        $string27_SharPersist_offensive_tool_keyword = /SchTaskBackdoor\./ nocase ascii wide
                        $string28_SharPersist_offensive_tool_keyword = "SharPersist -" nocase ascii wide
                        $string29_SharPersist_offensive_tool_keyword = "SharPersist" nocase ascii wide
                        $string30_SharPersist_offensive_tool_keyword = /SharPersist\.exe/ nocase ascii wide

    condition:
        any of them
}