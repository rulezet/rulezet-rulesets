rule rule_parrot_os_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'parrot os' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "parrot os"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_parrot_os_offensive_tool_keyword = " parrot main "
                        $string2_parrot_os_offensive_tool_keyword = /\sparrot\.run\//
                        $string3_parrot_os_offensive_tool_keyword = " parrot-backports "
                        $string4_parrot_os_offensive_tool_keyword = " parrot-security "
                        $string5_parrot_os_offensive_tool_keyword = /\/deb\.parrot\.sh\//
                        $string6_parrot_os_offensive_tool_keyword = /\/parrot\/iso\/.{0,100}\.iso/
                        $string7_parrot_os_offensive_tool_keyword = "/parrot-mirror/"
                        $string8_parrot_os_offensive_tool_keyword = "/parrot-on-docker/"
                        $string9_parrot_os_offensive_tool_keyword = "/parrotsec/"
                        $string10_parrot_os_offensive_tool_keyword = /bunny\.deb\.parrot\.sh\//
                        $string11_parrot_os_offensive_tool_keyword = /edge1\.parrot\.run/
                        $string12_parrot_os_offensive_tool_keyword = /mirrors\.aliyun\.com\/parrot/
                        $string13_parrot_os_offensive_tool_keyword = /parrot.{0,100}security\.vdi/
                        $string14_parrot_os_offensive_tool_keyword = /parrotsec\.org\/download\//
                        $string15_parrot_os_offensive_tool_keyword = /Parrot\-security\-.{0,100}\.iso/
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