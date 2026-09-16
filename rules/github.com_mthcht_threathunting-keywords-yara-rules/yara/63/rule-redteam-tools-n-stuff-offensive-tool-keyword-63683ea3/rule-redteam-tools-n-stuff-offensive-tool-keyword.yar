rule rule_RedTeam_Tools_n_Stuff_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RedTeam_Tools_n_Stuff' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedTeam_Tools_n_Stuff"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RedTeam_Tools_n_Stuff_offensive_tool_keyword = /\/DeleteonReboot\.exe/ nocase ascii wide
                        $string2_RedTeam_Tools_n_Stuff_offensive_tool_keyword = /\/RedTeam_Tools_n_Stuff\.git/ nocase ascii wide
                        $string3_RedTeam_Tools_n_Stuff_offensive_tool_keyword = /\/Vanity_Dump\.exe/ nocase ascii wide
                        $string4_RedTeam_Tools_n_Stuff_offensive_tool_keyword = /\\DeleteonReboot\.exe/ nocase ascii wide
                        $string5_RedTeam_Tools_n_Stuff_offensive_tool_keyword = /\\Vanity_Dump\.cpp/ nocase ascii wide
                        $string6_RedTeam_Tools_n_Stuff_offensive_tool_keyword = /\\Vanity_Dump\.exe/ nocase ascii wide
                        $string7_RedTeam_Tools_n_Stuff_offensive_tool_keyword = /\\Vanity_Dump\.sln/ nocase ascii wide
                        $string8_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "13ef95f2a3a43e67984999804e255ac93cdc9d9f8df85a188ba04700f6f4565c" nocase ascii wide
                        $string9_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "17332F12-D796-42D1-9A3E-460590A49382" nocase ascii wide
                        $string10_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "5782C660-DD26-40DC-B06C-B9275371EC55" nocase ascii wide
                        $string11_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "63957210-4871-42D3-B98A-191AF5F91079" nocase ascii wide
                        $string12_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "68ddd5703d6205313549d3828eeca64f383f297c43f65398f9a30637c07ef153" nocase ascii wide
                        $string13_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "b305da79a7ce7057b89449f9113577f0e3e0a2a5ecc67299a806b56b65418856" nocase ascii wide
                        $string14_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "C5C6F4EA-7F09-4AC7-AC2A-1246302B9856" nocase ascii wide
                        $string15_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "E51B9AEB-5F48-4C5C-837E-3A2743917427" nocase ascii wide
                        $string16_RedTeam_Tools_n_Stuff_offensive_tool_keyword = "RCStep/RedTeam_Tools_n_Stuff" nocase ascii wide

    condition:
        any of them
}