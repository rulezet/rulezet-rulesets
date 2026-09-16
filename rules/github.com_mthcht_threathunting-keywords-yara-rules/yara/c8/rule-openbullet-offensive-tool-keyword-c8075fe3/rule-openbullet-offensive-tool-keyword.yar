rule rule_openbullet_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'openbullet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openbullet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_openbullet_offensive_tool_keyword = /\/openbullet\.git/ nocase ascii wide
                        $string2_openbullet_offensive_tool_keyword = /\/OpenBullet2\.git/ nocase ascii wide
                        $string3_openbullet_offensive_tool_keyword = "0B6D8B01-861E-4CAF-B1C9-6670884381DB" nocase ascii wide
                        $string4_openbullet_offensive_tool_keyword = "99E40E7F-00A4-4FB1-9441-B05A56C47C08" nocase ascii wide
                        $string5_openbullet_offensive_tool_keyword = "C8482002-F594-4C28-9C46-960B036540A8" nocase ascii wide
                        $string6_openbullet_offensive_tool_keyword = /OpenBullet\.csproj/ nocase ascii wide
                        $string7_openbullet_offensive_tool_keyword = /OpenBullet\.exe/ nocase ascii wide
                        $string8_openbullet_offensive_tool_keyword = /OpenBullet\.pdb/ nocase ascii wide
                        $string9_openbullet_offensive_tool_keyword = /OpenBullet\.sln/ nocase ascii wide
                        $string10_openbullet_offensive_tool_keyword = /OpenBullet\.zip/ nocase ascii wide
                        $string11_openbullet_offensive_tool_keyword = "openbullet/openbullet" nocase ascii wide
                        $string12_openbullet_offensive_tool_keyword = /OpenBullet2\.Console\.zip/ nocase ascii wide
                        $string13_openbullet_offensive_tool_keyword = /OpenBullet2\.Native\.exe/ nocase ascii wide
                        $string14_openbullet_offensive_tool_keyword = /OpenBullet2\.Native\.zip/ nocase ascii wide
                        $string15_openbullet_offensive_tool_keyword = /OpenBullet2\.zip/ nocase ascii wide
                        $string16_openbullet_offensive_tool_keyword = "openbullet2:latest" nocase ascii wide
                        $string17_openbullet_offensive_tool_keyword = "OpenBullet2-master" nocase ascii wide
                        $string18_openbullet_offensive_tool_keyword = /OpenBulletApp\.cs/ nocase ascii wide
                        $string19_openbullet_offensive_tool_keyword = /OpenBulletCLI\.csproj/ nocase ascii wide
                        $string20_openbullet_offensive_tool_keyword = /OpenBulletCLI\.exe/ nocase ascii wide
                        $string21_openbullet_offensive_tool_keyword = "openbullet-master" nocase ascii wide
                        $string22_openbullet_offensive_tool_keyword = "Welcome to OpenBullet 2" nocase ascii wide
                        $string23_openbullet_offensive_tool_keyword = /Write\-Output\s127\.0\.0\.1\:1111/ nocase ascii wide
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