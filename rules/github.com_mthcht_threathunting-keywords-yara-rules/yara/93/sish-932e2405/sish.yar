rule sish
{
    meta:
        description = "Detection patterns for the tool 'sish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sish"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " sish -c date" nocase ascii wide
                        $string2 = "/_sish/console"
                        $string3 = /\/sish\.git/ nocase ascii wide
                        $string4 = /\/sish\.log/
                        $string5 = "/sish/cmd/"
                        $string6 = /\\sish\.log/ nocase ascii wide
                        $string7 = "eb0d8e4273608c13b5957ac047f911442b3d55527e20097cd038e120f01df5ae" nocase ascii wide
                        $string8 = /http\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
                        $string9 = /https\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
                        $string10 = "sish -x" nocase ascii wide
                        $string11 = /ssh\s\-L\s.{0,1000}\stuns\.sh/ nocase ascii wide
                        $string12 = /ssh\s\-R\s.{0,1000}\stuns\.sh/ nocase ascii wide
                        $string13 = /testing\.ssi\.sh/ nocase ascii wide

    condition:
        any of them
}