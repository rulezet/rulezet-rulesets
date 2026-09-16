rule rule_SMBCrunch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMBCrunch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBCrunch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMBCrunch_offensive_tool_keyword = /\s\-c\s.{0,100}\s\-s\s.{0,100}\s\-o\sshare_listing\s\-m\s150/ nocase ascii wide
                        $string2_SMBCrunch_offensive_tool_keyword = /\s\-i\sportscan445\.gnmap\s\-o\sshares_found\.txt/ nocase ascii wide
                        $string3_SMBCrunch_offensive_tool_keyword = /\sSMBGrab\.pl/ nocase ascii wide
                        $string4_SMBCrunch_offensive_tool_keyword = /\sSMBHunt\.pl/ nocase ascii wide
                        $string5_SMBCrunch_offensive_tool_keyword = /\sSMBList\.pl/ nocase ascii wide
                        $string6_SMBCrunch_offensive_tool_keyword = /\/SMBCrunch\.git/ nocase ascii wide
                        $string7_SMBCrunch_offensive_tool_keyword = /\/SMBGrab\.pl/ nocase ascii wide
                        $string8_SMBCrunch_offensive_tool_keyword = /\/SMBHunt\.pl/ nocase ascii wide
                        $string9_SMBCrunch_offensive_tool_keyword = /\/SMBList\.pl/ nocase ascii wide
                        $string10_SMBCrunch_offensive_tool_keyword = /\/tmp\/smb_auth_temp_.{0,100}\.txt/
                        $string11_SMBCrunch_offensive_tool_keyword = /\\SMBGrab\.pl/ nocase ascii wide
                        $string12_SMBCrunch_offensive_tool_keyword = /\\SMBHunt\.pl/ nocase ascii wide
                        $string13_SMBCrunch_offensive_tool_keyword = /\\SMBList\.pl/ nocase ascii wide
                        $string14_SMBCrunch_offensive_tool_keyword = /No\scredentials\ssupplied.{0,100}\slooking\sfor\snull\ssession\sshares\!/ nocase ascii wide
                        $string15_SMBCrunch_offensive_tool_keyword = "Raikia/SMBCrunch" nocase ascii wide
                        $string16_SMBCrunch_offensive_tool_keyword = /share_listing\/ALL_COMBINED_RESULTS\.TXT/ nocase ascii wide
                        $string17_SMBCrunch_offensive_tool_keyword = /smbclient\s\-N\s\-A\s.{0,100}\\\\\\\\.{0,100}\\\\.{0,100}temp_out\.txt/ nocase ascii wide
                        $string18_SMBCrunch_offensive_tool_keyword = "SMBCrunch-master" nocase ascii wide
                        $string19_SMBCrunch_offensive_tool_keyword = "Starting enumerating file shares using domain credential for " nocase ascii wide
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