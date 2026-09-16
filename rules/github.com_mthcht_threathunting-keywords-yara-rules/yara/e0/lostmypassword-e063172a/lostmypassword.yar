rule LostMyPassword
{
    meta:
        description = "Detection patterns for the tool 'LostMyPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LostMyPassword"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\LostMyPassword\.cfg/ nocase ascii wide
                        $string2 = /\\LostMyPassword_lng\.ini/ nocase ascii wide
                        $string3 = /\\LostMyPassword32bit/ nocase ascii wide
                        $string4 = ">LostMyPassword<" nocase ascii wide
                        $string5 = "73882b9c273a72eb49fc2854de8b37ef3012115c0e62267acb8b955a681ec312" nocase ascii wide
                        $string6 = "745bdc69fd7d712f65419c126b3ab5524fb96a511a21fea2d2b261607b3b2c55" nocase ascii wide
                        $string7 = "7da421d00cd50570a79a82803c170d043fa3b2253ae2f0697e103072c34d39f1" nocase ascii wide
                        $string8 = /LostMyPassword\.exe/ nocase ascii wide
                        $string9 = /LostMyPassword\.zip/ nocase ascii wide
                        $string10 = /LostMyPasswordx64\.zip/ nocase ascii wide
                        $string11 = "Search your passwords as normal user" nocase ascii wide

    condition:
        any of them
}