rule rule_ScriptBlock_Smuggling_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ScriptBlock-Smuggling' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScriptBlock-Smuggling"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ScriptBlock_Smuggling_offensive_tool_keyword = /\/ScriptBlock\-Smuggling\.git/ nocase ascii wide
                        $string2_ScriptBlock_Smuggling_offensive_tool_keyword = /\\ScriptBlock\-Smuggling/ nocase ascii wide
                        $string3_ScriptBlock_Smuggling_offensive_tool_keyword = /\\SmugglingCmdlet\.csproj/ nocase ascii wide
                        $string4_ScriptBlock_Smuggling_offensive_tool_keyword = /\\SmugglingCmdlet\.sln/ nocase ascii wide
                        $string5_ScriptBlock_Smuggling_offensive_tool_keyword = "360F9CE5-D927-46B9-8416-4118D0B68360" nocase ascii wide
                        $string6_ScriptBlock_Smuggling_offensive_tool_keyword = "4ffe43c71089a936b582e4840c196698a269e62e43a7a48ba3c53124809ab585" nocase ascii wide
                        $string7_ScriptBlock_Smuggling_offensive_tool_keyword = "5D4E7C1F-4812-4038-9663-6CD277ED9AD4" nocase ascii wide
                        $string8_ScriptBlock_Smuggling_offensive_tool_keyword = "76dc564506eb2419fffad94ca1eafd192f053261ec01d97848a259d15698d520" nocase ascii wide
                        $string9_ScriptBlock_Smuggling_offensive_tool_keyword = "779eedf10f0ae805b84e8cc0cd97f4861f0818eefa4ccf087d1c875db1d1c5e3" nocase ascii wide
                        $string10_ScriptBlock_Smuggling_offensive_tool_keyword = "BC-SECURITY/ScriptBlock-Smuggling" nocase ascii wide
                        $string11_ScriptBlock_Smuggling_offensive_tool_keyword = /ScriptBlockSmuggling\.ps1/ nocase ascii wide

    condition:
        any of them
}