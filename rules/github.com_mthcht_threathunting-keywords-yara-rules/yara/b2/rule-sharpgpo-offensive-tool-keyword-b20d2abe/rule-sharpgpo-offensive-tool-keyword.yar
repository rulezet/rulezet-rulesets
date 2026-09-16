rule rule_SharpGpo_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpGpo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGpo"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpGpo_offensive_tool_keyword = " --Action NewSecurityFiltering --GPOName " nocase ascii wide
                        $string2_SharpGpo_offensive_tool_keyword = " --Action RemoveSecurityFiltering --GPOName " nocase ascii wide
                        $string3_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sGetGPLink\s\-\-/ nocase ascii wide
                        $string4_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sGetGPO\s\-\-/ nocase ascii wide
                        $string5_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sMoveObject\s\-\-/ nocase ascii wide
                        $string6_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sNewGPLink\s\-\-DN\s/ nocase ascii wide
                        $string7_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sRemoveGPLink\s\-\-DN\s/ nocase ascii wide
                        $string8_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sRemoveGPO\s\-\-/ nocase ascii wide
                        $string9_SharpGpo_offensive_tool_keyword = /\.exe\s\-\-Action\sRemoveOU\s\-\-/ nocase ascii wide
                        $string10_SharpGpo_offensive_tool_keyword = /\/SharpGpo\.exe/ nocase ascii wide
                        $string11_SharpGpo_offensive_tool_keyword = /\\SharpGpo\.exe/ nocase ascii wide
                        $string12_SharpGpo_offensive_tool_keyword = /\\SharpGPOAbuse\-master/ nocase ascii wide
                        $string13_SharpGpo_offensive_tool_keyword = ">SharpGPO<" nocase ascii wide

    condition:
        any of them
}