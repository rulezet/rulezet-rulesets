rule rule_wiztree_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wiztree' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiztree"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_wiztree_greyware_tool_keyword = /\\Program\sFiles\\WizTree/ nocase ascii wide
                        $string2_wiztree_greyware_tool_keyword = /\\Temp\\WizTree\.exe/ nocase ascii wide
                        $string3_wiztree_greyware_tool_keyword = /\\WizTree\.exe/ nocase ascii wide
                        $string4_wiztree_greyware_tool_keyword = /\\wiztree_.{0,1000}_portable\.zip.{0,1000}	/ nocase ascii wide
                        $string5_wiztree_greyware_tool_keyword = /http\:\/\/antibody\-software\.com\/files\/wiztreeversion\.php/ nocase ascii wide
                        $string6_wiztree_greyware_tool_keyword = "WizTreeMutex" nocase ascii wide

    condition:
        any of them
}