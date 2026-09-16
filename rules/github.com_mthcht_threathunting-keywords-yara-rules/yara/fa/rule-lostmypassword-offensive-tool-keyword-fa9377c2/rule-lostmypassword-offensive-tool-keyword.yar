rule rule_LostMyPassword_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LostMyPassword' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LostMyPassword"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LostMyPassword_offensive_tool_keyword = /\\LostMyPassword\.cfg/ nocase ascii wide
                        $string2_LostMyPassword_offensive_tool_keyword = /\\LostMyPassword_lng\.ini/ nocase ascii wide
                        $string3_LostMyPassword_offensive_tool_keyword = /\\LostMyPassword32bit/ nocase ascii wide
                        $string4_LostMyPassword_offensive_tool_keyword = ">LostMyPassword<" nocase ascii wide
                        $string5_LostMyPassword_offensive_tool_keyword = "73882b9c273a72eb49fc2854de8b37ef3012115c0e62267acb8b955a681ec312" nocase ascii wide
                        $string6_LostMyPassword_offensive_tool_keyword = "745bdc69fd7d712f65419c126b3ab5524fb96a511a21fea2d2b261607b3b2c55" nocase ascii wide
                        $string7_LostMyPassword_offensive_tool_keyword = "7da421d00cd50570a79a82803c170d043fa3b2253ae2f0697e103072c34d39f1" nocase ascii wide
                        $string8_LostMyPassword_offensive_tool_keyword = /LostMyPassword\.exe/ nocase ascii wide
                        $string9_LostMyPassword_offensive_tool_keyword = /LostMyPassword\.zip/ nocase ascii wide
                        $string10_LostMyPassword_offensive_tool_keyword = /LostMyPasswordx64\.zip/ nocase ascii wide
                        $string11_LostMyPassword_offensive_tool_keyword = "Search your passwords as normal user" nocase ascii wide

    condition:
        any of them
}