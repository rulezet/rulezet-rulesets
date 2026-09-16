rule socat
{
    meta:
        description = "Detection patterns for the tool 'socat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "socat"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "socat exec:"
                        $string2 = /socat\sFILE\:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\sTCP.{0,1000}\:/
                        $string3 = /socat\sfile\:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\stcp\-listen\:/
                        $string4 = "socat http://0x0"
                        $string5 = /socat\s\-lp\s.{0,1000}\shttp\:\/\/0x0/
                        $string6 = "socat -O /tmp/"
                        $string7 = /socat\sTCP4\-LISTEN\:.{0,1000}\sfork\sTCP4\:.{0,1000}\:/
                        $string8 = "socat tcp-connect"
                        $string9 = /socat\stcp\-connect\:.{0,1000}\:.{0,1000}\sexec\:.{0,1000}bash\s\-li.{0,1000}.{0,1000}pty.{0,1000}stderr.{0,1000}setsid.{0,1000}sigint.{0,1000}sane/
                        $string10 = /socat\stcp\-connect\:.{0,1000}\:.{0,1000}\sexec\:\/bin\/sh/
                        $string11 = /socat\sTCP\-LISTEN\:.{0,1000}.{0,1000}reuseaddr.{0,1000}fork\sEXEC\:\/bin\/sh/

    condition:
        any of them
}