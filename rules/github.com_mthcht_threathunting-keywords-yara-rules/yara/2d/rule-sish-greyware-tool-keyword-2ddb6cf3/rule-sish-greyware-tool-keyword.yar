rule rule_sish_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sish"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sish_greyware_tool_keyword = " sish -c date" nocase ascii wide
                        $string2_sish_greyware_tool_keyword = "/_sish/console"
                        $string3_sish_greyware_tool_keyword = /\/sish\.git/ nocase ascii wide
                        $string4_sish_greyware_tool_keyword = /\/sish\.log/
                        $string5_sish_greyware_tool_keyword = "/sish/cmd/"
                        $string6_sish_greyware_tool_keyword = /\\sish\.log/ nocase ascii wide
                        $string7_sish_greyware_tool_keyword = "eb0d8e4273608c13b5957ac047f911442b3d55527e20097cd038e120f01df5ae" nocase ascii wide
                        $string8_sish_greyware_tool_keyword = /http\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
                        $string9_sish_greyware_tool_keyword = /https\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
                        $string10_sish_greyware_tool_keyword = "sish -x" nocase ascii wide
                        $string11_sish_greyware_tool_keyword = /ssh\s\-L\s.{0,1000}\stuns\.sh/ nocase ascii wide
                        $string12_sish_greyware_tool_keyword = /ssh\s\-R\s.{0,1000}\stuns\.sh/ nocase ascii wide
                        $string13_sish_greyware_tool_keyword = /testing\.ssi\.sh/ nocase ascii wide

    condition:
        any of them
}