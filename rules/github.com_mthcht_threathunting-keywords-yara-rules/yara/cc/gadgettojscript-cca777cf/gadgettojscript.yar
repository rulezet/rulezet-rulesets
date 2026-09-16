rule GadgetToJScript
{
    meta:
        description = "Detection patterns for the tool 'GadgetToJScript' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GadgetToJScript"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/GadgetToJScript\.git/ nocase ascii wide
                        $string2 = /\\shellcode_loader\.dll/ nocase ascii wide
                        $string3 = "AF9C62A1-F8D2-4BE0-B019-0A7873E81EA9" nocase ascii wide
                        $string4 = /GadgetToJScript\.csproj/ nocase ascii wide
                        $string5 = /GadgetToJScript\.sln/ nocase ascii wide
                        $string6 = "GadgetToJScript-master" nocase ascii wide
                        $string7 = "med0x2e/GadgetToJScript" nocase ascii wide

    condition:
        any of them
}