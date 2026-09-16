rule rule_Voidgate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Voidgate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Voidgate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Voidgate_offensive_tool_keyword = /\/Voidgate\.exe/ nocase ascii wide
                        $string2_Voidgate_offensive_tool_keyword = /\/Voidgate\.git/ nocase ascii wide
                        $string3_Voidgate_offensive_tool_keyword = /\\Voidgate\.cpp/ nocase ascii wide
                        $string4_Voidgate_offensive_tool_keyword = /\\Voidgate\.exe/ nocase ascii wide
                        $string5_Voidgate_offensive_tool_keyword = /\\voidgate\-master\\/ nocase ascii wide
                        $string6_Voidgate_offensive_tool_keyword = /\\Windows\\temp\\payload\.bin/ nocase ascii wide
                        $string7_Voidgate_offensive_tool_keyword = "15bdbbebff7a58257d1cd0ade5d76877259c2b3152508f1b2534a6fcab89cb38" nocase ascii wide
                        $string8_Voidgate_offensive_tool_keyword = "39fa3b4151fd83044106b63e95a820f4f1d769714d4f73369dba7a2187e0918b" nocase ascii wide
                        $string9_Voidgate_offensive_tool_keyword = "bba575ec-0c7f-42e1-9b59-b7c9cca522ba" nocase ascii wide
                        $string10_Voidgate_offensive_tool_keyword = "c06bb3f0-cbdc-4384-84cf-21b7fe6dfe01" nocase ascii wide
                        $string11_Voidgate_offensive_tool_keyword = "vxCrypt0r/Voidgate" nocase ascii wide
                        $string12_Voidgate_offensive_tool_keyword = /XorEncryptPayload\.cpp/ nocase ascii wide
                        $string13_Voidgate_offensive_tool_keyword = /XorEncryptPayload\.exe/ nocase ascii wide
                        $string14_Voidgate_offensive_tool_keyword = /XorEncryptPayload\.vcxproj/ nocase ascii wide

    condition:
        any of them
}