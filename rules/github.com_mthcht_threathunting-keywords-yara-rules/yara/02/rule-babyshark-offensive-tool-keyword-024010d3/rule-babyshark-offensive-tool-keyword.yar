rule rule_BabyShark_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BabyShark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BabyShark"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BabyShark_offensive_tool_keyword = /\/BabyShark\.git/ nocase ascii wide
                        $string2_BabyShark_offensive_tool_keyword = "/home/daddyShark/BabySh4rk/"
                        $string3_BabyShark_offensive_tool_keyword = /\/momyshark\.html/ nocase ascii wide
                        $string4_BabyShark_offensive_tool_keyword = /\/momyshark\?key\=/ nocase ascii wide
                        $string5_BabyShark_offensive_tool_keyword = /\/momyshark\?key\=/ nocase ascii wide
                        $string6_BabyShark_offensive_tool_keyword = /\/sharklog\.log/
                        $string7_BabyShark_offensive_tool_keyword = /\\BabyShark\-master\.zip/ nocase ascii wide
                        $string8_BabyShark_offensive_tool_keyword = "283516d3927c180b3f4b8d90cefaaf34ff66a5250f218fa327e194f71748e015" nocase ascii wide
                        $string9_BabyShark_offensive_tool_keyword = "7716e96debd76da60e286c09150ced547e6e7ed8cba8231d0612d92941833591" nocase ascii wide
                        $string10_BabyShark_offensive_tool_keyword = "78be236127f4f8c65a8a9818b43e32e33a9107325e14b80f53337cd34b8c53e8" nocase ascii wide
                        $string11_BabyShark_offensive_tool_keyword = "BabySh4rk - MomySh4rk" nocase ascii wide
                        $string12_BabyShark_offensive_tool_keyword = "danilovazb/BabyShark" nocase ascii wide
                        $string13_BabyShark_offensive_tool_keyword = /database\/c2\.db/ nocase ascii wide
                        $string14_BabyShark_offensive_tool_keyword = "password = 'b4bysh4rk'" nocase ascii wide
                        $string15_BabyShark_offensive_tool_keyword = /sqlite3\sdatabase\/c2\.db/ nocase ascii wide
                        $string16_BabyShark_offensive_tool_keyword = /translate\.google\.com\/translate\?\&anno\=2\&u\=\$c2server/ nocase ascii wide
                        $string17_BabyShark_offensive_tool_keyword = "UnkL4b/BabyShark" nocase ascii wide

    condition:
        any of them
}