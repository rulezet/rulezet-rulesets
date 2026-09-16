rule rule_adexplorer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adexplorer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adexplorer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_adexplorer_greyware_tool_keyword = /\\Software\\MSDART\\Active\sDirectory\sExplorer/ nocase ascii wide
                        $string2_adexplorer_greyware_tool_keyword = /\\Software\\Sysinternals\\Active\sDirectory\sExplorer/ nocase ascii wide
                        $string3_adexplorer_greyware_tool_keyword = "<Data Name='OriginalFileName'>AdExp<" nocase ascii wide
                        $string4_adexplorer_greyware_tool_keyword = ">Active Directory Editor<" nocase ascii wide
                        $string5_adexplorer_greyware_tool_keyword = ">Sysinternals ADExplorer<" nocase ascii wide
                        $string6_adexplorer_greyware_tool_keyword = /adexplorer\.exe/ nocase ascii wide
                        $string7_adexplorer_greyware_tool_keyword = /adexplorer\.zip/ nocase ascii wide
                        $string8_adexplorer_greyware_tool_keyword = /adexplorer64\.exe/ nocase ascii wide
                        $string9_adexplorer_greyware_tool_keyword = /adexplorer64a\.exe/ nocase ascii wide

    condition:
        any of them
}