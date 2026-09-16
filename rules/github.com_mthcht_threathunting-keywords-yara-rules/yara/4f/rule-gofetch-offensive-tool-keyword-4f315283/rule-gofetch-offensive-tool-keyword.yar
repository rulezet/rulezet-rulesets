rule rule_GoFetch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GoFetch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoFetch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GoFetch_offensive_tool_keyword = /\s\-pathToBloodHoundGraph\s.{0,1000}\s\-pathToOutputGoFetchPath\s.{0,1000}\s\-pathToAdditionalPayload\s/ nocase ascii wide
                        $string2_GoFetch_offensive_tool_keyword = /\s\-PathToGraph\s.{0,1000}\.json\s\-PathToPayload\s.{0,1000}\.exe/ nocase ascii wide
                        $string3_GoFetch_offensive_tool_keyword = /\/gofetch\.exe/ nocase ascii wide
                        $string4_GoFetch_offensive_tool_keyword = /\/GoFetch\.git/ nocase ascii wide
                        $string5_GoFetch_offensive_tool_keyword = /\\gofetch\.exe/ nocase ascii wide
                        $string6_GoFetch_offensive_tool_keyword = /\\GoFetchLog\.log/ nocase ascii wide
                        $string7_GoFetch_offensive_tool_keyword = /\\GoFetch\-main/ nocase ascii wide
                        $string8_GoFetch_offensive_tool_keyword = /\\PsExecLog\.log/ nocase ascii wide
                        $string9_GoFetch_offensive_tool_keyword = "1615016050f681f61f692ef54d34a26911587fff98fa6ee1f945f1ecd04e2705"
                        $string10_GoFetch_offensive_tool_keyword = "7c37604dd86dc2ce14b352c8df0c4230ab3a1887ef73349806b0e7c15025843c" nocase ascii wide
                        $string11_GoFetch_offensive_tool_keyword = "BloodHoundGraphToGoFetchPath" nocase ascii wide
                        $string12_GoFetch_offensive_tool_keyword = "GoFetchAD/GoFetch" nocase ascii wide
                        $string13_GoFetch_offensive_tool_keyword = "Invoke-GoFetch" nocase ascii wide

    condition:
        any of them
}