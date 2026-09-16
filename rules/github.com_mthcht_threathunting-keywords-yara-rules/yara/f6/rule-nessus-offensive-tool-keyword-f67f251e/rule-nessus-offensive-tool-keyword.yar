rule rule_nessus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nessus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nessus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nessus_offensive_tool_keyword = "/opt/nessus/" nocase ascii wide
                        $string2_nessus_offensive_tool_keyword = /log4shell.{0,100}\.nessus\.org/ nocase ascii wide
                        $string3_nessus_offensive_tool_keyword = /nessus.{0,100}\s\-\-set\slisten_address\=127\.0\.0\.1/ nocase ascii wide
                        $string4_nessus_offensive_tool_keyword = /Nessus\-.{0,100}\.deb/ nocase ascii wide
                        $string5_nessus_offensive_tool_keyword = /Nessus\-.{0,100}\.dmg/ nocase ascii wide
                        $string6_nessus_offensive_tool_keyword = /Nessus\-.{0,100}\.msi/ nocase ascii wide
                        $string7_nessus_offensive_tool_keyword = /Nessus\-.{0,100}\.rpm/ nocase ascii wide
                        $string8_nessus_offensive_tool_keyword = /Nessus\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string9_nessus_offensive_tool_keyword = /Nessus\-.{0,100}\.txz/ nocase ascii wide
                        $string10_nessus_offensive_tool_keyword = "nessuscli fetch"
                        $string11_nessus_offensive_tool_keyword = "nessuscli fix"
                        $string12_nessus_offensive_tool_keyword = /nessus\-updates.{0,100}\.tar\.gz/ nocase ascii wide
                        $string13_nessus_offensive_tool_keyword = /plugins\.nessus\.org\./ nocase ascii wide
                        $string14_nessus_offensive_tool_keyword = "systemctl start nessusd"
                        $string15_nessus_offensive_tool_keyword = /tenable\.com\/downloads\/nessus/ nocase ascii wide
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