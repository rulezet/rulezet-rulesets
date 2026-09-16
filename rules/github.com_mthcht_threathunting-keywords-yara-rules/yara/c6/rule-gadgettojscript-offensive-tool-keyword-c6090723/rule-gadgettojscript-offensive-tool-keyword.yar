rule rule_GadgetToJScript_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GadgetToJScript' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GadgetToJScript"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_GadgetToJScript_offensive_tool_keyword = /\/GadgetToJScript\.git/ nocase ascii wide
                        $string2_GadgetToJScript_offensive_tool_keyword = /\\shellcode_loader\.dll/ nocase ascii wide
                        $string3_GadgetToJScript_offensive_tool_keyword = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" nocase ascii wide
                        $string4_GadgetToJScript_offensive_tool_keyword = /GadgetToJScript\.csproj/ nocase ascii wide
                        $string5_GadgetToJScript_offensive_tool_keyword = /GadgetToJScript\.sln/ nocase ascii wide
                        $string6_GadgetToJScript_offensive_tool_keyword = "GadgetToJScript-master" nocase ascii wide
                        $string7_GadgetToJScript_offensive_tool_keyword = "med0x2e/GadgetToJScript" nocase ascii wide

    condition:
        any of them
}