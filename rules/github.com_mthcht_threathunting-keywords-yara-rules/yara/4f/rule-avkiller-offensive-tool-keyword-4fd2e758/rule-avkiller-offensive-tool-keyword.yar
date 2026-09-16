rule rule_AVKiller_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AVKiller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AVKiller"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AVKiller_offensive_tool_keyword = /\/AVKiller\.git/ nocase ascii wide
                        $string2_AVKiller_offensive_tool_keyword = "1y0n/AVKiller" nocase ascii wide
                        $string3_AVKiller_offensive_tool_keyword = "6eac306cec3650ed8740d82024380ccaaea2ac4b8f6b55119a9e5fb82485f67f" nocase ascii wide
                        $string4_AVKiller_offensive_tool_keyword = "ba99e7ff67fb59ab551943030c912a2dfa0c9f1e1bba2c3e53a71aa5348386ec" nocase ascii wide
                        $string5_AVKiller_offensive_tool_keyword = "dd35d7c7b99d5a0a182ff16546ebee8af08ee92510157d6f02355bae256d6191" nocase ascii wide
                        $string6_AVKiller_offensive_tool_keyword = /https\:\/\/mp\.weixin\.qq\.com\/s\/GDPAC_9\-Pxfcj_z0_C_ixw/ nocase ascii wide
                        $string7_AVKiller_offensive_tool_keyword = /TerminateProcessFromId\(ID\(\\"360rp\.exe\\"\)/ nocase ascii wide
                        $string8_AVKiller_offensive_tool_keyword = /TerminateProcessFromId\(ID\(\\"360rps\.exe\\"\)/ nocase ascii wide
                        $string9_AVKiller_offensive_tool_keyword = /TerminateProcessFromId\(ID\(\\"360sd\.exe\\"\)/ nocase ascii wide
                        $string10_AVKiller_offensive_tool_keyword = /TerminateProcessFromId\(ID\(\\"360tray\.exe\\"\)/ nocase ascii wide
                        $string11_AVKiller_offensive_tool_keyword = /TerminateProcessFromId\(ID\(\\"ZhuDongFangYu\.exe\\"\)/ nocase ascii wide

    condition:
        any of them
}