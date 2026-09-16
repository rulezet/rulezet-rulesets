rule rule_Necro_Stealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Necro-Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Necro-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Necro_Stealer_offensive_tool_keyword = /\/Necro\-Stealer\.git/ nocase ascii wide
                        $string2_Necro_Stealer_offensive_tool_keyword = /\\Necro\-Stealer\-.{0,1000}\.zip/ nocase ascii wide
                        $string3_Necro_Stealer_offensive_tool_keyword = "a568c8a8c28b7ceeee2f5eec82f94dd4fb0fc06175b2ee3043f863a68451ebbd" nocase ascii wide
                        $string4_Necro_Stealer_offensive_tool_keyword = "ac3107cf-291c-449b-9121-55cd37f6383e" nocase ascii wide
                        $string5_Necro_Stealer_offensive_tool_keyword = "d14be0c5477fc937b2cc00367931e1181d8897ce98a560cff48e0939840a096b" nocase ascii wide
                        $string6_Necro_Stealer_offensive_tool_keyword = /NecroStealer\.exe/ nocase ascii wide
                        $string7_Necro_Stealer_offensive_tool_keyword = "SecUser1/Necro-Stealer" nocase ascii wide

    condition:
        any of them
}