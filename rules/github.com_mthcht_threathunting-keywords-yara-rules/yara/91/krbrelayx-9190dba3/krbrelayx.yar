rule krbrelayx
{
    meta:
        description = "Detection patterns for the tool 'krbrelayx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "krbrelayx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --dump-adcs" nocase ascii wide
                        $string2 = " --dump-gmsa" nocase ascii wide
                        $string3 = " --dump-laps" nocase ascii wide
                        $string4 = " --enum-local-admins" nocase ascii wide
                        $string5 = " -f kirbi " nocase ascii wide
                        $string6 = " --format kirbi" nocase ascii wide
                        $string7 = /\s\-\-krbpass\s.{0,1000}\-\-krbsalt/ nocase ascii wide
                        $string8 = /\/dnstool\.py/ nocase ascii wide
                        $string9 = "/krbrelayx" nocase ascii wide
                        $string10 = /\/printerbug\.py/ nocase ascii wide
                        $string11 = /addspn\.py/ nocase ascii wide
                        $string12 = /\-hashes.{0,1000}\s\-\-escalate\-user/ nocase ascii wide
                        $string13 = /krbrelayx\.git/ nocase ascii wide
                        $string14 = /krbrelayx\.py/ nocase ascii wide
                        $string15 = "krbrelayx-master" nocase ascii wide

    condition:
        any of them
}