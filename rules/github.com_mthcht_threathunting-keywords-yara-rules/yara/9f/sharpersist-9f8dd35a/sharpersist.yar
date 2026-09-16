rule SharPersist
{
    meta:
        description = "Detection patterns for the tool 'SharPersist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharPersist"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " keepass backdoor persistence" nocase ascii wide
                        $string2 = " Keepass persistence backdoor " nocase ascii wide
                        $string3 = " -t schtaskbackdoor " nocase ascii wide
                        $string4 = /\.exe\s\-t\skeepass\s\-f\s/ nocase ascii wide
                        $string5 = /\.exe\s\-t\sstartupfolder\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-f/ nocase ascii wide
                        $string6 = /\.exe\s\-t\stortoisesvn\s\-c\s.{0,1000}\s\-a\s.{0,1000}\s\-m/ nocase ascii wide
                        $string7 = /\/SharPersist\.git/ nocase ascii wide
                        $string8 = /\\SchTaskBackdoor\./ nocase ascii wide
                        $string9 = /\\SharPersist\\/ nocase ascii wide
                        $string10 = /\\TortoiseSVNHookScripts\.cs/ nocase ascii wide
                        $string11 = "7806b81514ecc44219a6f6193b15b23aea0a947f3c91b339332bea1445745596" nocase ascii wide
                        $string12 = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" nocase ascii wide
                        $string13 = /c\:\\123\.txt/ nocase ascii wide
                        $string14 = "e9711f47cf9171f79bf34b342279f6fd9275c8ae65f3eb2c6ebb0b8432ea14f8" nocase ascii wide
                        $string15 = "INFO: Adding keepass backdoor persistence" nocase ascii wide
                        $string16 = "INFO: Adding registry persistence" nocase ascii wide
                        $string17 = "INFO: Adding scheduled task backdoor persistence" nocase ascii wide
                        $string18 = "INFO: Adding scheduled task persistence" nocase ascii wide
                        $string19 = "INFO: Adding service persistence" nocase ascii wide
                        $string20 = "INFO: Adding startup folder persistence" nocase ascii wide
                        $string21 = "INFO: Adding tortoise svn persistence" nocase ascii wide
                        $string22 = "INFO: Checking backdoor present in KeePass config file" nocase ascii wide
                        $string23 = /INFO\:\sListing\sall\sscheduled\stasks\savailable\sto\sbackdoor\./ nocase ascii wide
                        $string24 = "KeePass config file is backdoored already" nocase ascii wide
                        $string25 = /KeePassBackdoor\./ nocase ascii wide
                        $string26 = "mandiant/SharPersist" nocase ascii wide
                        $string27 = /SchTaskBackdoor\./ nocase ascii wide
                        $string28 = "SharPersist -" nocase ascii wide
                        $string29 = "SharPersist" nocase ascii wide
                        $string30 = /SharPersist\.exe/ nocase ascii wide

    condition:
        any of them
}