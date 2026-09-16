rule ETW
{
    meta:
        description = "Detection patterns for the tool 'ETW' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ETW"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\$env\:COMPlus_ETWEnabled\=0/ nocase ascii wide
                        $string2 = /COMPlus_ETWEnabled\=0\\0\\0\\0/ nocase ascii wide
                        $string3 = /env_var_spoofing_poc\.cpp/ nocase ascii wide
                        $string4 = "set COMPlus_ETWEnabled=0" nocase ascii wide

    condition:
        any of them
}