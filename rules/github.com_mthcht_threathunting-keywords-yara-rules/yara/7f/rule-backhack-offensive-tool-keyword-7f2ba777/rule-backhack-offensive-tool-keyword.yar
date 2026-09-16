rule rule_BackHAck_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BackHAck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackHAck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BackHAck_offensive_tool_keyword = /\sbackhack\.py/
                        $string2_BackHAck_offensive_tool_keyword = /\/BackHAck\.git/
                        $string3_BackHAck_offensive_tool_keyword = /\/backhack\.py/
                        $string4_BackHAck_offensive_tool_keyword = /\\backhack\.py/
                        $string5_BackHAck_offensive_tool_keyword = "48c4df943d19bc547c6cab3a3c802dbcf13af3b7880b3977aef74f452c831a95"
                        $string6_BackHAck_offensive_tool_keyword = "93df885410ce2b2ea1428127077bcf574e56838ce8ccf4ea410a1f120544f9b8"
                        $string7_BackHAck_offensive_tool_keyword = "AngelSecurityTeam/BackHAck"
                        $string8_BackHAck_offensive_tool_keyword = "AngelSecurityTeam-BackdoorLinux"
                        $string9_BackHAck_offensive_tool_keyword = /AngelSecurityTeam\-BackdoorWindows\.exe/
                        $string10_BackHAck_offensive_tool_keyword = /AngelSecurityTeam\-BackdoorWindows\.exe/
                        $string11_BackHAck_offensive_tool_keyword = /curl\s\-s\s\-N\shttp\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/
                        $string12_BackHAck_offensive_tool_keyword = /https\:\/\/bin\.equinox\.io\/c\/4VmDzA7iaHb\//
                        $string13_BackHAck_offensive_tool_keyword = /ngrok\-stable\-linux\-arm\.zip/
                        $string14_BackHAck_offensive_tool_keyword = /python3\s\-m\shttp\.server\s80\s\>\s\.server\s2\>\s\/dev\/null/

    condition:
        any of them
}