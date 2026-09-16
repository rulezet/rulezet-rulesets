rule ppldump
{
    meta:
        description = "Detection patterns for the tool 'ppldump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ppldump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "6E8D2C12-255B-403C-9EF3-8A097D374DB2" nocase ascii wide
                        $string2 = /dllexploit\./ nocase ascii wide
                        $string3 = "FCE81BDA-ACAC-4892-969E-0414E765593B" nocase ascii wide
                        $string4 = /lsass\.exe.{0,1000}\.dmp/ nocase ascii wide
                        $string5 = "PPLdump" nocase ascii wide
                        $string6 = /PPLdump\.exe/ nocase ascii wide
                        $string7 = /PPLdump64\.exe/ nocase ascii wide
                        $string8 = "PPLdumpDll" nocase ascii wide

    condition:
        any of them
}