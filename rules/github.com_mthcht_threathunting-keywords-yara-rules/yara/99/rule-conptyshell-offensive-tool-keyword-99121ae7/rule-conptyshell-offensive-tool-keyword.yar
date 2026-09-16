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
                        $string16_ConPtyShell_offensive_tool_keyword = /\-RemoteIp\s.{0,100}\s\-RemotePort\s.{0,100}\s\-Rows\s.{0,100}\s\-Cols\s.{0,100}\s\-CommandLine\s.{0,100}\.exe/ nocase ascii wide
                        $string17_ConPtyShell_offensive_tool_keyword = /SocketHijacking\./ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}