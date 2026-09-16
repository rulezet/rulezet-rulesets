rule rule_rsg_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rsg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsg"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rsg_offensive_tool_keyword = " nc -n -v -l -s "
                        $string2_rsg_offensive_tool_keyword = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\./ nocase ascii wide
                        $string3_rsg_offensive_tool_keyword = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
                        $string4_rsg_offensive_tool_keyword = "/bin/sh -i <&3 >&3 2>&3"
                        $string5_rsg_offensive_tool_keyword = "/usr/local/bin/rsg"
                        $string6_rsg_offensive_tool_keyword = "64cd8640e2b53358f8fbafbcbded6db53e1acd49fe4ccc8196c8ed17c551bc70" nocase ascii wide
                        $string7_rsg_offensive_tool_keyword = "b3804cac36175125199ddd8f6840749ead5c723d9641670d244d0a487fcf555c" nocase ascii wide
                        $string8_rsg_offensive_tool_keyword = "ebdac49d15f37cc60cb5e755b10743512ececf134126e0ac4a024cb1149ae76f" nocase ascii wide
                        $string9_rsg_offensive_tool_keyword = /mthbernardes.{0,100}rsg/ nocase ascii wide
                        $string10_rsg_offensive_tool_keyword = "mthbernardes/rsg" nocase ascii wide
                        $string11_rsg_offensive_tool_keyword = "nc -c /bin/sh "
                        $string12_rsg_offensive_tool_keyword = /php\s\-r\s.{0,100}fsockopen.{0,100}exec\(.{0,100}\/bin\/sh/
                        $string13_rsg_offensive_tool_keyword = /powershell\s\-nop\s\-c\s\\"\\"\$client\s\=\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
                        $string14_rsg_offensive_tool_keyword = /ruby\s\-rsocket\s\-e\s\'.{0,100}\=TCPSocket\.new\(/ nocase ascii wide
                        $string15_rsg_offensive_tool_keyword = /socat\.exe\s\-d\s\-d\sTCP4\:/ nocase ascii wide
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