rule rule_HRShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HRShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HRShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HRShell_offensive_tool_keyword = /\sclient\.py\s\-s\shttp.{0,1000}\:5000\s\-\-cert\s\/.{0,1000}\.pem/ nocase ascii wide
                        $string2_HRShell_offensive_tool_keyword = /\sserver\.py\s\-s\stornado\s\-\-cert\s\/.{0,1000}pem\s\-\-key\s\/.{0,1000}\.pem/ nocase ascii wide
                        $string3_HRShell_offensive_tool_keyword = /\/HRShell\.git/ nocase ascii wide
                        $string4_HRShell_offensive_tool_keyword = "/HRShell/" nocase ascii wide
                        $string5_HRShell_offensive_tool_keyword = "/meterpreter/reverse_tcp" nocase ascii wide
                        $string6_HRShell_offensive_tool_keyword = /\/shellcodes\/utils\.py/ nocase ascii wide
                        $string7_HRShell_offensive_tool_keyword = "chrispetrou/HRShell" nocase ascii wide
                        $string8_HRShell_offensive_tool_keyword = "exploit -j -z" nocase ascii wide
                        $string9_HRShell_offensive_tool_keyword = "from shellcodes import " nocase ascii wide
                        $string10_HRShell_offensive_tool_keyword = "history_cmd" nocase ascii wide
                        $string11_HRShell_offensive_tool_keyword = /HRShell.{0,1000}client\.py/ nocase ascii wide
                        $string12_HRShell_offensive_tool_keyword = /HRShell.{0,1000}server\.py/ nocase ascii wide
                        $string13_HRShell_offensive_tool_keyword = "inject shellcode" nocase ascii wide
                        $string14_HRShell_offensive_tool_keyword = "set shellcode " nocase ascii wide
                        $string15_HRShell_offensive_tool_keyword = "set_shellcode" nocase ascii wide
                        $string16_HRShell_offensive_tool_keyword = /shellcode1\s\+\=\sb/ nocase ascii wide
                        $string17_HRShell_offensive_tool_keyword = "set shellcode " nocase ascii wide

    condition:
        any of them
}