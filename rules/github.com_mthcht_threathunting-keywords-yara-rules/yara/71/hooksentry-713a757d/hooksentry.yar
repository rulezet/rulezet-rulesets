rule HookSentry
{
    meta:
        description = "Detection patterns for the tool 'HookSentry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HookSentry"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/HookSentry\.exe/ nocase ascii wide
                        $string2 = /\/HookSentry\.git/ nocase ascii wide
                        $string3 = "050243af07ab26ee16ed59f35a1d7944db273a40aba1c3e70438c3a8e0d2a923" nocase ascii wide
                        $string4 = "b6aa7aa16083b7113fe5fe662a497c6c03a3c4aa74ff2c379b64fd9e9b495bcf" nocase ascii wide
                        $string5 = "ce613fc8-3f97-4989-bc90-2027463ea37d" nocase ascii wide
                        $string6 = "UmaRex01/HookSentry" nocase ascii wide

    condition:
        any of them
}