rule Aoyama_
{
    meta:
        description = "Detection patterns for the tool 'Aoyama ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Aoyama "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "#Code By Leeon123" nocase ascii wide
                        $string2 = /\[\!\]\sSetting\sUp\sC\&C\sModule/ nocase ascii wide
                        $string3 = /\[\!\]\sWelcom\sto\sthe\sAoyama\sC\&C\sServer/ nocase ascii wide
                        $string4 = "==> Python3 C&C server <==" nocase ascii wide
                        $string5 = "43f5ef8c625efba630bb99fd4ae086008ebed5c2f3386f1b43bbe8ee7c06f591" nocase ascii wide
                        $string6 = "Leeon123/Aoyama" nocase ascii wide
                        $string7 = "Leeon123/Python3-botnet" nocase ascii wide
                        $string8 = /python3\scnc\.py/ nocase ascii wide
                        $string9 = "rm -rf /bin/netstat"
                        $string10 = /rm\s\-rf\s\~\/\.bash_history/
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