rule Procdump
{
    meta:
        description = "Detection patterns for the tool 'Procdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Procdump"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-ma\slssas\.exe/ nocase ascii wide
                        $string2 = /\/Procdump\.zip/ nocase ascii wide
                        $string3 = /\\lsass\.dmp/ nocase ascii wide
                        $string4 = /\\Procdump\.zip/ nocase ascii wide
                        $string5 = /\\SOFTWARE\\Sysinternals\\ProcDump\\/ nocase ascii wide
                        $string6 = /\\Users\\Public\\.{0,1000}\.dmp/ nocase ascii wide
                        $string7 = /\<Data\sName\=\'PipeName\'\>\\lsass\<\/Data\>\<Data\sName\=\'Image\'\>.{0,1000}procdump.{0,1000}\<\/Data\>/ nocase ascii wide
                        $string8 = ">ProcDump<" nocase ascii wide
                        $string9 = /procdump.{0,1000}lsass/ nocase ascii wide
                        $string10 = /procdump.{0,1000}lsass/ nocase ascii wide
                        $string11 = /procdump\.exe.{0,1000}\s\-ma/ nocase ascii wide
                        $string12 = /procdump64.{0,1000}lsass/ nocase ascii wide
                        $string13 = /procdump64\.exe/ nocase ascii wide

    condition:
        any of them
}