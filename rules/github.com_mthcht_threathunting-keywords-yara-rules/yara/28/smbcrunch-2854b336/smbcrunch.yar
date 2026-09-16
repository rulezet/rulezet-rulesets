rule SMBCrunch
{
    meta:
        description = "Detection patterns for the tool 'SMBCrunch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBCrunch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-c\s.{0,100}\s\-s\s.{0,100}\s\-o\sshare_listing\s\-m\s150/ nocase ascii wide
                        $string2 = /\s\-i\sportscan445\.gnmap\s\-o\sshares_found\.txt/ nocase ascii wide
                        $string3 = /\sSMBGrab\.pl/ nocase ascii wide
                        $string4 = /\sSMBHunt\.pl/ nocase ascii wide
                        $string5 = /\sSMBList\.pl/ nocase ascii wide
                        $string6 = /\/SMBCrunch\.git/ nocase ascii wide
                        $string7 = /\/SMBGrab\.pl/ nocase ascii wide
                        $string8 = /\/SMBHunt\.pl/ nocase ascii wide
                        $string9 = /\/SMBList\.pl/ nocase ascii wide
                        $string10 = /\/tmp\/smb_auth_temp_.{0,100}\.txt/
                        $string11 = /\\SMBGrab\.pl/ nocase ascii wide
                        $string12 = /\\SMBHunt\.pl/ nocase ascii wide
                        $string13 = /\\SMBList\.pl/ nocase ascii wide
                        $string14 = /No\scredentials\ssupplied.{0,100}\slooking\sfor\snull\ssession\sshares\!/ nocase ascii wide
                        $string15 = "Raikia/SMBCrunch" nocase ascii wide
                        $string16 = /share_listing\/ALL_COMBINED_RESULTS\.TXT/ nocase ascii wide
                        $string17 = /smbclient\s\-N\s\-A\s.{0,100}\\\\\\\\.{0,100}\\\\.{0,100}temp_out\.txt/ nocase ascii wide
                        $string18 = "SMBCrunch-master" nocase ascii wide
                        $string19 = "Starting enumerating file shares using domain credential for " nocase ascii wide
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