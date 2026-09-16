rule adexplorer
{
    meta:
        description = "Detection patterns for the tool 'adexplorer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adexplorer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\Software\\MSDART\\Active\sDirectory\sExplorer/ nocase ascii wide
                        $string2 = /\\Software\\Sysinternals\\Active\sDirectory\sExplorer/ nocase ascii wide
                        $string3 = "<Data Name='OriginalFileName'>AdExp<" nocase ascii wide
                        $string4 = ">Active Directory Editor<" nocase ascii wide
                        $string5 = ">Sysinternals ADExplorer<" nocase ascii wide
                        $string6 = /adexplorer\.exe/ nocase ascii wide
                        $string7 = /adexplorer\.zip/ nocase ascii wide
                        $string8 = /adexplorer64\.exe/ nocase ascii wide
                        $string9 = /adexplorer64a\.exe/ nocase ascii wide

    condition:
        any of them
}