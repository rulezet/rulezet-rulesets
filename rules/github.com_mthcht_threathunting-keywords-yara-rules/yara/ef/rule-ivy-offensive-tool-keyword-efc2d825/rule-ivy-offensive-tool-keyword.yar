rule rule_ivy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ivy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ivy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-O\s.{0,100}\.png\s\-stageless/ nocase ascii wide
                        $string2_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.hta\s\-url\shttp\:.{0,100}\s\-delivery\shta\s\-stageless/ nocase ascii wide
                        $string3_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.js\s\-url\shttp.{0,100}\s\-delivery\sbits\s\-stageless/ nocase ascii wide
                        $string4_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.txt\s\-url\shttp.{0,100}\s\-delivery\smacro\s\-stageless/ nocase ascii wide
                        $string5_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.xsl\s\-url\shttp.{0,100}\s\-delivery\sxsl\s\-stageless/ nocase ascii wide
                        $string6_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,100}\.c\s\-Ix86\s.{0,100}\.c\s\-P\sLocal\s\-O\s.{0,100}\.js/ nocase ascii wide
                        $string7_ivy_offensive_tool_keyword = /\s\-Ix64\s.{0,100}\.vba\s\-Ix86\s.{0,100}\.vba\s\-P\sInject\s\-O\s/ nocase ascii wide
                        $string8_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-O\s.{0,100}\.js/ nocase ascii wide
                        $string9_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-process64\s.{0,100}\.exe\s\-O\s.{0,100}\.js/ nocase ascii wide
                        $string10_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sInject\s\-unhook\s\-O\s.{0,100}\.js/ nocase ascii wide
                        $string11_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-O\s.{0,100}\.js/ nocase ascii wide
                        $string12_ivy_offensive_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,100}\.bin\s\-Ix86\s.{0,100}\.bin\s\-P\sLocal\s\-unhook\s\-O\s.{0,100}\.js/ nocase ascii wide
                        $string13_ivy_offensive_tool_keyword = /\.\/Ivy\s\-/
                        $string14_ivy_offensive_tool_keyword = "/Ivy/Cryptor" nocase ascii wide
                        $string15_ivy_offensive_tool_keyword = "/Ivy/Loader/" nocase ascii wide
                        $string16_ivy_offensive_tool_keyword = /\\Ivy\\Cryptor/ nocase ascii wide
                        $string17_ivy_offensive_tool_keyword = /\\Ivy\\Loader\\/ nocase ascii wide
                        $string18_ivy_offensive_tool_keyword = "7267a9321dd7ab890af5892975e257f89b2e53c70216c3708be9b0418e6b470e" nocase ascii wide
                        $string19_ivy_offensive_tool_keyword = /go\sbuild\sIvy\.go/ nocase ascii wide
                        $string20_ivy_offensive_tool_keyword = /Ivy_1.{0,100}_darwin_amd64/
                        $string21_ivy_offensive_tool_keyword = /Ivy_1.{0,100}_linux_amd64/
                        $string22_ivy_offensive_tool_keyword = /Ivy_1.{0,100}_windows_amd64\.exe/ nocase ascii wide
                        $string23_ivy_offensive_tool_keyword = /Ivy\-main\.zip/ nocase ascii wide
                        $string24_ivy_offensive_tool_keyword = /optiv\/Ivy\.git/ nocase ascii wide
                        $string25_ivy_offensive_tool_keyword = "Tylous/Ivy" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}