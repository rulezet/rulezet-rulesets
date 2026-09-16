rule SOAPHound
{
    meta:
        description = "Detection patterns for the tool 'SOAPHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SOAPHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --bhdump " nocase ascii wide
                        $string2 = " --certdump " nocase ascii wide
                        $string3 = " --dnsdump " nocase ascii wide
                        $string4 = /\sSOAPHound\.ADWS/ nocase ascii wide
                        $string5 = /\\"ADWS\srequest\swith\sldapbase\s\(/ nocase ascii wide
                        $string6 = "\"Dump BH data\"" nocase ascii wide
                        $string7 = /\(\!soaphound\=/ nocase ascii wide
                        $string8 = /\.exe\s\s\-\-buildcache\s\-c\s.{0,1000}\\cache\.txt/ nocase ascii wide
                        $string9 = /\.exe\s\-\-showstats\s\-c\s.{0,1000}\\cache\.txt/ nocase ascii wide
                        $string10 = /\/SOAPHound\.exe/ nocase ascii wide
                        $string11 = /\/SOAPHound\.git/ nocase ascii wide
                        $string12 = /\/SOAPHound\/Program\.cs/ nocase ascii wide
                        $string13 = /\\SOAPHound\.csproj/ nocase ascii wide
                        $string14 = /\\SOAPHound\.exe/ nocase ascii wide
                        $string15 = /\\SOAPHound\.sln/ nocase ascii wide
                        $string16 = /\\SOAPHound\\Enums\\/ nocase ascii wide
                        $string17 = /\\SOAPHound\\Program\.cs/ nocase ascii wide
                        $string18 = /\\SOAPHound\-master/ nocase ascii wide
                        $string19 = "33571B09-4E94-43CB-ABDC-0226D769E701" nocase ascii wide
                        $string20 = /Domain\scontroller\sis\smissing.{0,1000}\suse\s\-\-dc\./ nocase ascii wide
                        $string21 = "Dump AD Certificate Services data" nocase ascii wide
                        $string22 = "Dump AD Integrated DNS data" nocase ascii wide
                        $string23 = "FalconForceTeam/SOAPHound" nocase ascii wide
                        $string24 = "Password to use for ADWS Connection" nocase ascii wide
                        $string25 = /SOAPHound\sPoC\s1\.0\.1\-beta/ nocase ascii wide
                        $string26 = /SOAPHound\.exe\s/ nocase ascii wide
                        $string27 = /SOAPHound\.Processors/ nocase ascii wide
                        $string28 = "Specify domain for enumeration" nocase ascii wide
                        $string29 = /Username\sto\suse\sfor\sADWS\sConnection\.\sFormat\:\sdomain\\\\user\sor\suser\@domain/ nocase ascii wide

    condition:
        any of them
}