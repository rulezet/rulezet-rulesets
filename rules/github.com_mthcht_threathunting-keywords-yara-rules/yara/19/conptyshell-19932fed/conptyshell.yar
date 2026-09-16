rule ConPtyShell
{
    meta:
        description = "Detection patterns for the tool 'ConPtyShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ConPtyShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " ConPtyShell" nocase ascii wide
                        $string2 = /\$parametersConPtyShell/ nocase ascii wide
                        $string3 = "/ConPtyShell/" nocase ascii wide
                        $string4 = "376713183026ccc822e9c1dead28cc81c7cfa7ad1c88e368ada6c31ce3909a2e" nocase ascii wide
                        $string5 = "antonioCoco/ConPtyShell" nocase ascii wide
                        $string6 = /ConPtyShell\.cs/ nocase ascii wide
                        $string7 = /ConPtyShell\.exe/ nocase ascii wide
                        $string8 = /ConPtyShell\.git/ nocase ascii wide
                        $string9 = /ConPtyShell\.zip/ nocase ascii wide
                        $string10 = /ConPtyShell\.zip/ nocase ascii wide
                        $string11 = /ConPtyShell_dotnet2\.exe/ nocase ascii wide
                        $string12 = "CreatePseudoConsole function found! Spawning a fully interactive shell" nocase ascii wide
                        $string13 = "CreatePseudoConsole function not found! Spawning a netcat-like interactive shell" nocase ascii wide
                        $string14 = "Invoke-ConPtyShell" nocase ascii wide
                        $string15 = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
                        $string16 = /\-RemoteIp\s.{0,1000}\s\-RemotePort\s.{0,1000}\s\-Rows\s.{0,1000}\s\-Cols\s.{0,1000}\s\-CommandLine\s.{0,1000}\.exe/ nocase ascii wide
                        $string17 = /SocketHijacking\./ nocase ascii wide

    condition:
        any of them
}