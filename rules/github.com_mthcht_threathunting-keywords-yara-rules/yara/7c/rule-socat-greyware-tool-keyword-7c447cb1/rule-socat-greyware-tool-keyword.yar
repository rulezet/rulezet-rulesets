rule rule_socat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'socat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "socat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_socat_greyware_tool_keyword = "socat exec:"
                        $string2_socat_greyware_tool_keyword = /socat\sFILE\:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\sTCP.{0,1000}\:/
                        $string3_socat_greyware_tool_keyword = /socat\sfile\:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\stcp\-listen\:/
                        $string4_socat_greyware_tool_keyword = "socat http://0x0"
                        $string5_socat_greyware_tool_keyword = /socat\s\-lp\s.{0,1000}\shttp\:\/\/0x0/
                        $string6_socat_greyware_tool_keyword = "socat -O /tmp/"
                        $string7_socat_greyware_tool_keyword = /socat\sTCP4\-LISTEN\:.{0,1000}\sfork\sTCP4\:.{0,1000}\:/
                        $string8_socat_greyware_tool_keyword = "socat tcp-connect"
                        $string9_socat_greyware_tool_keyword = /socat\stcp\-connect\:.{0,1000}\:.{0,1000}\sexec\:.{0,1000}bash\s\-li.{0,1000}.{0,1000}pty.{0,1000}stderr.{0,1000}setsid.{0,1000}sigint.{0,1000}sane/
                        $string10_socat_greyware_tool_keyword = /socat\stcp\-connect\:.{0,1000}\:.{0,1000}\sexec\:\/bin\/sh/
                        $string11_socat_greyware_tool_keyword = /socat\sTCP\-LISTEN\:.{0,1000}.{0,1000}reuseaddr.{0,1000}fork\sEXEC\:\/bin\/sh/

    condition:
        any of them
}