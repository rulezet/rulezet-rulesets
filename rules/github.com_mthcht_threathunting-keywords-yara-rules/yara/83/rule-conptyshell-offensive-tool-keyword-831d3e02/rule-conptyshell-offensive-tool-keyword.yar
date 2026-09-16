rule rule_ConPtyShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ConPtyShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ConPtyShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ConPtyShell_offensive_tool_keyword = " ConPtyShell" nocase ascii wide
                        $string2_ConPtyShell_offensive_tool_keyword = /\$parametersConPtyShell/ nocase ascii wide
                        $string3_ConPtyShell_offensive_tool_keyword = "/ConPtyShell/" nocase ascii wide
                        $string4_ConPtyShell_offensive_tool_keyword = "376713183026ccc822e9c1dead28cc81c7cfa7ad1c88e368ada6c31ce3909a2e" nocase ascii wide
                        $string5_ConPtyShell_offensive_tool_keyword = "antonioCoco/ConPtyShell" nocase ascii wide
                        $string6_ConPtyShell_offensive_tool_keyword = /ConPtyShell\.cs/ nocase ascii wide
                        $string7_ConPtyShell_offensive_tool_keyword = /ConPtyShell\.exe/ nocase ascii wide
                        $string8_ConPtyShell_offensive_tool_keyword = /ConPtyShell\.git/ nocase ascii wide
                        $string9_ConPtyShell_offensive_tool_keyword = /ConPtyShell\.zip/ nocase ascii wide
                        $string10_ConPtyShell_offensive_tool_keyword = /ConPtyShell\.zip/ nocase ascii wide
                        $string11_ConPtyShell_offensive_tool_keyword = /ConPtyShell_dotnet2\.exe/ nocase ascii wide
                        $string12_ConPtyShell_offensive_tool_keyword = "CreatePseudoConsole function found! Spawning a fully interactive shell" nocase ascii wide
                        $string13_ConPtyShell_offensive_tool_keyword = "CreatePseudoConsole function not found! Spawning a netcat-like interactive shell" nocase ascii wide
                        $string14_ConPtyShell_offensive_tool_keyword = "Invoke-ConPtyShell" nocase ascii wide
                        $string15_ConPtyShell_offensive_tool_keyword = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
                        $string16_ConPtyShell_offensive_tool_keyword = /\-RemoteIp\s.{0,1000}\s\-RemotePort\s.{0,1000}\s\-Rows\s.{0,1000}\s\-Cols\s.{0,1000}\s\-CommandLine\s.{0,1000}\.exe/ nocase ascii wide
                        $string17_ConPtyShell_offensive_tool_keyword = /SocketHijacking\./ nocase ascii wide

    condition:
        any of them
}