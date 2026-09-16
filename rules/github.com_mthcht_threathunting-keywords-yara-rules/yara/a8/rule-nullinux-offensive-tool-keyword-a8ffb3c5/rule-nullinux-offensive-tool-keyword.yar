rule rule_nullinux_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nullinux' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nullinux"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nullinux_offensive_tool_keyword = /\snullinux\.py/
                        $string2_nullinux_offensive_tool_keyword = /\/nullinux\.git/
                        $string3_nullinux_offensive_tool_keyword = /\/nullinux\.py/
                        $string4_nullinux_offensive_tool_keyword = /\/nullinux_users\.txt/
                        $string5_nullinux_offensive_tool_keyword = "/usr/local/bin/nullinux"
                        $string6_nullinux_offensive_tool_keyword = /\]\sStarting\snullinux\ssetup\sscript/
                        $string7_nullinux_offensive_tool_keyword = "e4df5a904c8eb505cb63d9905c398f632cf97ba193a6e25569d561d44f69e623"
                        $string8_nullinux_offensive_tool_keyword = /enum_enumdomusers\(/
                        $string9_nullinux_offensive_tool_keyword = "m8sec/nullinux"
                        $string10_nullinux_offensive_tool_keyword = "nullinux -rid -range "
                        $string11_nullinux_offensive_tool_keyword = "nullinux -shares -U "
                        $string12_nullinux_offensive_tool_keyword = "nullinux -users "
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