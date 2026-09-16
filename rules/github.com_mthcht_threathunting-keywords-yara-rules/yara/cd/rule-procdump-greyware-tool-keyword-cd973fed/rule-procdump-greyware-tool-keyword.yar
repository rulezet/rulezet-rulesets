rule rule_Procdump_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Procdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Procdump"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Procdump_greyware_tool_keyword = /\s\-ma\slssas\.exe/ nocase ascii wide
                        $string2_Procdump_greyware_tool_keyword = /\/Procdump\.zip/ nocase ascii wide
                        $string3_Procdump_greyware_tool_keyword = /\\lsass\.dmp/ nocase ascii wide
                        $string4_Procdump_greyware_tool_keyword = /\\Procdump\.zip/ nocase ascii wide
                        $string5_Procdump_greyware_tool_keyword = /\\SOFTWARE\\Sysinternals\\ProcDump\\/ nocase ascii wide
                        $string6_Procdump_greyware_tool_keyword = /\\Users\\Public\\.{0,1000}\.dmp/ nocase ascii wide
                        $string7_Procdump_greyware_tool_keyword = /\<Data\sName\=\'PipeName\'\>\\lsass\<\/Data\>\<Data\sName\=\'Image\'\>.{0,1000}procdump.{0,1000}\<\/Data\>/ nocase ascii wide
                        $string8_Procdump_greyware_tool_keyword = ">ProcDump<" nocase ascii wide
                        $string9_Procdump_greyware_tool_keyword = /procdump.{0,1000}lsass/ nocase ascii wide
                        $string10_Procdump_greyware_tool_keyword = /procdump.{0,1000}lsass/ nocase ascii wide
                        $string11_Procdump_greyware_tool_keyword = /procdump\.exe.{0,1000}\s\-ma/ nocase ascii wide
                        $string12_Procdump_greyware_tool_keyword = /procdump64.{0,1000}lsass/ nocase ascii wide
                        $string13_Procdump_greyware_tool_keyword = /procdump64\.exe/ nocase ascii wide

    condition:
        any of them
}