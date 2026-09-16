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
                        $string2_socat_greyware_tool_keyword = /socat\sFILE\:.{0,100}tty.{0,100}raw.{0,100}echo\=0\sTCP.{0,100}\:/
                        $string3_socat_greyware_tool_keyword = /socat\sfile\:.{0,100}tty.{0,100}raw.{0,100}echo\=0\stcp\-listen\:/
                        $string4_socat_greyware_tool_keyword = "socat http://0x0"
                        $string5_socat_greyware_tool_keyword = /socat\s\-lp\s.{0,100}\shttp\:\/\/0x0/
                        $string6_socat_greyware_tool_keyword = "socat -O /tmp/"
                        $string7_socat_greyware_tool_keyword = /socat\sTCP4\-LISTEN\:.{0,100}\sfork\sTCP4\:.{0,100}\:/
                        $string8_socat_greyware_tool_keyword = "socat tcp-connect"
                        $string9_socat_greyware_tool_keyword = /socat\stcp\-connect\:.{0,100}\:.{0,100}\sexec\:.{0,100}bash\s\-li.{0,100}.{0,100}pty.{0,100}stderr.{0,100}setsid.{0,100}sigint.{0,100}sane/
                        $string10_socat_greyware_tool_keyword = /socat\stcp\-connect\:.{0,100}\:.{0,100}\sexec\:\/bin\/sh/
                        $string11_socat_greyware_tool_keyword = /socat\sTCP\-LISTEN\:.{0,100}.{0,100}reuseaddr.{0,100}fork\sEXEC\:\/bin\/sh/
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