rule rule_ppldump_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ppldump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ppldump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ppldump_offensive_tool_keyword = "6E8D2C12-255B-403C-9EF3-8A097D374DB2" nocase ascii wide
                        $string2_ppldump_offensive_tool_keyword = /dllexploit\./ nocase ascii wide
                        $string3_ppldump_offensive_tool_keyword = "FCE81BDA-ACAC-4892-969E-0414E765593B" nocase ascii wide
                        $string4_ppldump_offensive_tool_keyword = /lsass\.exe.{0,1000}\.dmp/ nocase ascii wide
                        $string5_ppldump_offensive_tool_keyword = "PPLdump" nocase ascii wide
                        $string6_ppldump_offensive_tool_keyword = /PPLdump\.exe/ nocase ascii wide
                        $string7_ppldump_offensive_tool_keyword = /PPLdump64\.exe/ nocase ascii wide
                        $string8_ppldump_offensive_tool_keyword = "PPLdumpDll" nocase ascii wide

    condition:
        any of them
}