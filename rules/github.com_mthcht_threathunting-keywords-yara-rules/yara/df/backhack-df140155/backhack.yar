rule BackHAck
{
    meta:
        description = "Detection patterns for the tool 'BackHAck' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackHAck"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbackhack\.py/
                        $string2 = /\/BackHAck\.git/
                        $string3 = /\/backhack\.py/
                        $string4 = /\\backhack\.py/
                        $string5 = "48c4df943d19bc547c6cab3a3c802dbcf13af3b7880b3977aef74f452c831a95"
                        $string6 = "93df885410ce2b2ea1428127077bcf574e56838ce8ccf4ea410a1f120544f9b8"
                        $string7 = "AngelSecurityTeam/BackHAck"
                        $string8 = "AngelSecurityTeam-BackdoorLinux"
                        $string9 = /AngelSecurityTeam\-BackdoorWindows\.exe/
                        $string10 = /AngelSecurityTeam\-BackdoorWindows\.exe/
                        $string11 = /curl\s\-s\s\-N\shttp\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/
                        $string12 = /https\:\/\/bin\.equinox\.io\/c\/4VmDzA7iaHb\//
                        $string13 = /ngrok\-stable\-linux\-arm\.zip/
                        $string14 = /python3\s\-m\shttp\.server\s80\s\>\s\.server\s2\>\s\/dev\/null/

    condition:
        any of them
}