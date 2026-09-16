rule BabyShark
{
    meta:
        description = "Detection patterns for the tool 'BabyShark' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BabyShark"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BabyShark\.git/ nocase ascii wide
                        $string2 = "/home/daddyShark/BabySh4rk/"
                        $string3 = /\/momyshark\.html/ nocase ascii wide
                        $string4 = /\/momyshark\?key\=/ nocase ascii wide
                        $string5 = /\/momyshark\?key\=/ nocase ascii wide
                        $string6 = /\/sharklog\.log/
                        $string7 = /\\BabyShark\-master\.zip/ nocase ascii wide
                        $string8 = "283516d3927c180b3f4b8d90cefaaf34ff66a5250f218fa327e194f71748e015" nocase ascii wide
                        $string9 = "7716e96debd76da60e286c09150ced547e6e7ed8cba8231d0612d92941833591" nocase ascii wide
                        $string10 = "78be236127f4f8c65a8a9818b43e32e33a9107325e14b80f53337cd34b8c53e8" nocase ascii wide
                        $string11 = "BabySh4rk - MomySh4rk" nocase ascii wide
                        $string12 = "danilovazb/BabyShark" nocase ascii wide
                        $string13 = /database\/c2\.db/ nocase ascii wide
                        $string14 = "password = 'b4bysh4rk'" nocase ascii wide
                        $string15 = /sqlite3\sdatabase\/c2\.db/ nocase ascii wide
                        $string16 = /translate\.google\.com\/translate\?\&anno\=2\&u\=\$c2server/ nocase ascii wide
                        $string17 = "UnkL4b/BabyShark" nocase ascii wide

    condition:
        any of them
}