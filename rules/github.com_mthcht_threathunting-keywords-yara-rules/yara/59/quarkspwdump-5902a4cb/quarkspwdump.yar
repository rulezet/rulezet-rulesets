rule quarkspwdump
{
    meta:
        description = "Detection patterns for the tool 'quarkspwdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "quarkspwdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --dump-bitlocker " nocase ascii wide
                        $string2 = " --dump-bitlocker" nocase ascii wide
                        $string3 = " --dump-hash-domain --with-history" nocase ascii wide
                        $string4 = " --dump-hash-domain" nocase ascii wide
                        $string5 = " --dump-hash-domain-cached" nocase ascii wide
                        $string6 = " --dump-hash-domain-cached" nocase ascii wide
                        $string7 = " --dump-hash-local" nocase ascii wide
                        $string8 = " --ntds-file " nocase ascii wide
                        $string9 = /\/quarkspwdump\.git/ nocase ascii wide
                        $string10 = /\/quarkspwdump\.git/ nocase ascii wide
                        $string11 = /\[\+\]\sLSAKEY\(s\)\sretrieving/ nocase ascii wide
                        $string12 = /\[\+\]\sParsing\sSAM\sregistry\shive/ nocase ascii wide
                        $string13 = /\[\+\]\sParsing\sSAM\sregistry\shive/ nocase ascii wide
                        $string14 = /\[\+\]\sParsing\sSECURITY\sregistry\shive/ nocase ascii wide
                        $string15 = /\[\+\]\sParsing\sSECURITY\sregistry\shive/ nocase ascii wide
                        $string16 = /\[\+\]\sSYSKEY\srestrieving/ nocase ascii wide
                        $string17 = /\[\+\]\sSYSKEY\srestrieving/ nocase ascii wide
                        $string18 = /\\QuarksADDumper\./ nocase ascii wide
                        $string19 = /\\QuarksPwDump/ nocase ascii wide
                        $string20 = /\\QUARKS\-SAM/ nocase ascii wide
                        $string21 = /\\SAM\-.{0,1000}\.dmp/ nocase ascii wide
                        $string22 = /\\SAM\-.{0,1000}\.dmp\.LOG/ nocase ascii wide
                        $string23 = "07a00b5f4f4d8fd3328b5454dc101d4e76126d9e2600ca2d6fd677452bf624d7" nocase ascii wide
                        $string24 = "07a00b5f4f4d8fd3328b5454dc101d4e76126d9e2600ca2d6fd677452bf624d7" nocase ascii wide
                        $string25 = /ATT_BITLOCKER_MSFVE_RECOVERY_PASSWORD.{0,1000}ATTm591788/ nocase ascii wide
                        $string26 = /azizjon\.m\@gmail\.com/ nocase ascii wide
                        $string27 = "d14884d8a7f74e96a4450e1b1e65636b3a2810274963e4a6eb28e161effe1216" nocase ascii wide
                        $string28 = "d14884d8a7f74e96a4450e1b1e65636b3a2810274963e4a6eb28e161effe1216" nocase ascii wide
                        $string29 = /\-\-dump\-bitlocker.{0,1000}\-\-ntds\-file\s/ nocase ascii wide
                        $string30 = "E0362605-CC11-4CD5-AFF7-B50934438658" nocase ascii wide
                        $string31 = "E0362605-CC11-4CD5-AFF7-B50934438658" nocase ascii wide
                        $string32 = "No cached domain password found!" nocase ascii wide
                        $string33 = "peterdocter/quarkspwdump" nocase ascii wide
                        $string34 = "QuarksADDumper" nocase ascii wide
                        $string35 = "quarkslab/quarkspwdump" nocase ascii wide
                        $string36 = /quarks\-pwdump\.exe/ nocase ascii wide
                        $string37 = /quarks\-pwdump\.exe/ nocase ascii wide

    condition:
        any of them
}