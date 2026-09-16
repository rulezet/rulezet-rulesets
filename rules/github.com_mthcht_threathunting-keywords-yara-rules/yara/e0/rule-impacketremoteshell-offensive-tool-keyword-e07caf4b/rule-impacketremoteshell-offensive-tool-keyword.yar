rule rule_impacketremoteshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'impacketremoteshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacketremoteshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_impacketremoteshell_offensive_tool_keyword = /\sremoteshell\.py/ nocase ascii wide
                        $string2_impacketremoteshell_offensive_tool_keyword = /\/RemoteMaintsvc\.exe/ nocase ascii wide
                        $string3_impacketremoteshell_offensive_tool_keyword = /\/RemoteMaintsvc\.exe/ nocase ascii wide
                        $string4_impacketremoteshell_offensive_tool_keyword = /\/remoteshell\.py/ nocase ascii wide
                        $string5_impacketremoteshell_offensive_tool_keyword = /\\\\\.\\pipe\\RemoteMaint/ nocase ascii wide
                        $string6_impacketremoteshell_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\RemoteMaint/ nocase ascii wide
                        $string7_impacketremoteshell_offensive_tool_keyword = /\\RemoteMaint\.sln/ nocase ascii wide
                        $string8_impacketremoteshell_offensive_tool_keyword = /\\RemoteMaint\.vcxproj/ nocase ascii wide
                        $string9_impacketremoteshell_offensive_tool_keyword = /\\RemoteMaintsvc\.exe/ nocase ascii wide
                        $string10_impacketremoteshell_offensive_tool_keyword = /\\RemoteMaintsvc\.exe/ nocase ascii wide
                        $string11_impacketremoteshell_offensive_tool_keyword = /\\remoteshell\.py/ nocase ascii wide
                        $string12_impacketremoteshell_offensive_tool_keyword = "037f7348a66495d6502220e15f3766aa070dd12eb40b3d08d3f855c4cd77cf7f" nocase ascii wide
                        $string13_impacketremoteshell_offensive_tool_keyword = "11ef63b9bc33b0da6d0b5593e55e460aa8aa8279eb9ad4b90a4dc2b722ffa6e1" nocase ascii wide
                        $string14_impacketremoteshell_offensive_tool_keyword = "9e85c971331b8ad686c8d79ea81c4883d3f36a7de2071551fe5369fcf34ea3d0" nocase ascii wide
                        $string15_impacketremoteshell_offensive_tool_keyword = "CE23F388-34F5-4543-81D1-91CD244C9CB1" nocase ascii wide
                        $string16_impacketremoteshell_offensive_tool_keyword = /impacket\.internal_helpers/ nocase ascii wide
                        $string17_impacketremoteshell_offensive_tool_keyword = /impacket\.smbconnection/ nocase ascii wide
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