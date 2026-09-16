rule rule_UnstoppableService_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UnstoppableService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnstoppableService"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_UnstoppableService_offensive_tool_keyword = "\"ServiceName = \"\"unstoppable\"" nocase ascii wide
                        $string2_UnstoppableService_offensive_tool_keyword = /\/UnstoppableService\.git/ nocase ascii wide
                        $string3_UnstoppableService_offensive_tool_keyword = /\\UnstoppableService\.csproj/ nocase ascii wide
                        $string4_UnstoppableService_offensive_tool_keyword = /\\UnstoppableService\.sln/ nocase ascii wide
                        $string5_UnstoppableService_offensive_tool_keyword = /\\UnstoppableService\-master/ nocase ascii wide
                        $string6_UnstoppableService_offensive_tool_keyword = "0C117EE5-2A21-496D-AF31-8CC7F0CAAA86" nocase ascii wide
                        $string7_UnstoppableService_offensive_tool_keyword = "4889b9e1fa6c34ea86e56253135093b390919aa006f8cd3fa372b410f2f1e5bf" nocase ascii wide
                        $string8_UnstoppableService_offensive_tool_keyword = "8e66227e48270913e40edcabdaa2d20332572f8ca6d066737e4ae3984d66b591" nocase ascii wide
                        $string9_UnstoppableService_offensive_tool_keyword = "malcomvetter/UnstoppableService" nocase ascii wide
                        $string10_UnstoppableService_offensive_tool_keyword = /Provides\san\sunstoppable\sWindows\sService\sExperience\.\sLorem\sIpsum\sDolor/ nocase ascii wide

    condition:
        any of them
}