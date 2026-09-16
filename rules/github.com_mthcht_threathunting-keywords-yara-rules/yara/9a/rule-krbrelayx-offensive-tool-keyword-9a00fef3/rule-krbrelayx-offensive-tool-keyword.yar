rule rule_krbrelayx_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'krbrelayx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krbrelayx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_krbrelayx_offensive_tool_keyword = " --dump-adcs" nocase ascii wide
                        $string2_krbrelayx_offensive_tool_keyword = " --dump-gmsa" nocase ascii wide
                        $string3_krbrelayx_offensive_tool_keyword = " --dump-laps" nocase ascii wide
                        $string4_krbrelayx_offensive_tool_keyword = " --enum-local-admins" nocase ascii wide
                        $string5_krbrelayx_offensive_tool_keyword = " -f kirbi " nocase ascii wide
                        $string6_krbrelayx_offensive_tool_keyword = " --format kirbi" nocase ascii wide
                        $string7_krbrelayx_offensive_tool_keyword = /\s\-\-krbpass\s.{0,1000}\-\-krbsalt/ nocase ascii wide
                        $string8_krbrelayx_offensive_tool_keyword = /\/dnstool\.py/ nocase ascii wide
                        $string9_krbrelayx_offensive_tool_keyword = "/krbrelayx" nocase ascii wide
                        $string10_krbrelayx_offensive_tool_keyword = /\/printerbug\.py/ nocase ascii wide
                        $string11_krbrelayx_offensive_tool_keyword = /addspn\.py/ nocase ascii wide
                        $string12_krbrelayx_offensive_tool_keyword = /\-hashes.{0,1000}\s\-\-escalate\-user/ nocase ascii wide
                        $string13_krbrelayx_offensive_tool_keyword = /krbrelayx\.git/ nocase ascii wide
                        $string14_krbrelayx_offensive_tool_keyword = /krbrelayx\.py/ nocase ascii wide
                        $string15_krbrelayx_offensive_tool_keyword = "krbrelayx-master" nocase ascii wide

    condition:
        any of them
}