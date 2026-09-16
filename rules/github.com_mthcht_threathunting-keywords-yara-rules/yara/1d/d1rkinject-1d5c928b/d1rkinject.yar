rule D1rkInject
{
    meta:
        description = "Detection patterns for the tool 'D1rkInject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D1rkInject"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/D1rkInject\.git/ nocase ascii wide
                        $string2 = /\/MalStuff\.cpp/ nocase ascii wide
                        $string3 = /\\D1rkInject\\/ nocase ascii wide
                        $string4 = /\\MalStuff\.cpp/ nocase ascii wide
                        $string5 = "APT stands for Advanced Persistence Tomato" nocase ascii wide
                        $string6 = "BD602C80-47ED-4294-B981-0119D2200DB8" nocase ascii wide
                        $string7 = /D1rkInject\.cpp/ nocase ascii wide
                        $string8 = /D1rkInject\.exe/ nocase ascii wide
                        $string9 = /D1rkInject\.iobj/ nocase ascii wide
                        $string10 = /D1rkInject\.log/ nocase ascii wide
                        $string11 = /D1rkInject\.sln/ nocase ascii wide
                        $string12 = /D1rkInject\.vcxproj/ nocase ascii wide
                        $string13 = "D1rkInject-main" nocase ascii wide
                        $string14 = "EEC35BCF-E990-4260-828D-2B4F9AC97269" nocase ascii wide
                        $string15 = "TheD1rkMtr/D1rkInject" nocase ascii wide

    condition:
        any of them
}