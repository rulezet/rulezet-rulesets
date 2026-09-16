rule HRShell
{
    meta:
        description = "Detection patterns for the tool 'HRShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HRShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sclient\.py\s\-s\shttp.{0,1000}\:5000\s\-\-cert\s\/.{0,1000}\.pem/ nocase ascii wide
                        $string2 = /\sserver\.py\s\-s\stornado\s\-\-cert\s\/.{0,1000}pem\s\-\-key\s\/.{0,1000}\.pem/ nocase ascii wide
                        $string3 = /\/HRShell\.git/ nocase ascii wide
                        $string4 = "/HRShell/" nocase ascii wide
                        $string5 = "/meterpreter/reverse_tcp" nocase ascii wide
                        $string6 = /\/shellcodes\/utils\.py/ nocase ascii wide
                        $string7 = "chrispetrou/HRShell" nocase ascii wide
                        $string8 = "exploit -j -z" nocase ascii wide
                        $string9 = "from shellcodes import " nocase ascii wide
                        $string10 = "history_cmd" nocase ascii wide
                        $string11 = /HRShell.{0,1000}client\.py/ nocase ascii wide
                        $string12 = /HRShell.{0,1000}server\.py/ nocase ascii wide
                        $string13 = "inject shellcode" nocase ascii wide
                        $string14 = "set shellcode " nocase ascii wide
                        $string15 = "set_shellcode" nocase ascii wide
                        $string16 = /shellcode1\s\+\=\sb/ nocase ascii wide
                        $string17 = "set shellcode " nocase ascii wide

    condition:
        any of them
}