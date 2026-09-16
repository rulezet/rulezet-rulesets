rule rule_creddump7_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'creddump7' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "creddump7"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_creddump7_offensive_tool_keyword = /\scachedump\.py/ nocase ascii wide
                        $string2_creddump7_offensive_tool_keyword = /\sdomcachedump\.py/ nocase ascii wide
                        $string3_creddump7_offensive_tool_keyword = " install creddump7" nocase ascii wide
                        $string4_creddump7_offensive_tool_keyword = /\slsadump\.py/ nocase ascii wide
                        $string5_creddump7_offensive_tool_keyword = /\slsasecrets\.py/ nocase ascii wide
                        $string6_creddump7_offensive_tool_keyword = /\spwdump\.py/ nocase ascii wide
                        $string7_creddump7_offensive_tool_keyword = /\/cachedump\.py/ nocase ascii wide
                        $string8_creddump7_offensive_tool_keyword = /\/creddump7\.git/ nocase ascii wide
                        $string9_creddump7_offensive_tool_keyword = /\/creddump7\.git/ nocase ascii wide
                        $string10_creddump7_offensive_tool_keyword = "/creddump7/releases/" nocase ascii wide
                        $string11_creddump7_offensive_tool_keyword = /\/domcachedump\.py/ nocase ascii wide
                        $string12_creddump7_offensive_tool_keyword = /\/lsadump\.py/ nocase ascii wide
                        $string13_creddump7_offensive_tool_keyword = /\/lsasecrets\.py/ nocase ascii wide
                        $string14_creddump7_offensive_tool_keyword = /\/pwdump\.py/ nocase ascii wide
                        $string15_creddump7_offensive_tool_keyword = /\\cachedump\.py/ nocase ascii wide
                        $string16_creddump7_offensive_tool_keyword = /\\creddump7\-master/ nocase ascii wide
                        $string17_creddump7_offensive_tool_keyword = /\\domcachedump\.py/ nocase ascii wide
                        $string18_creddump7_offensive_tool_keyword = /\\lsadump\.py/ nocase ascii wide
                        $string19_creddump7_offensive_tool_keyword = /\\lsasecrets\.py/ nocase ascii wide
                        $string20_creddump7_offensive_tool_keyword = /\\pwdump\.py/ nocase ascii wide
                        $string21_creddump7_offensive_tool_keyword = "17723167fed5ac513f66d4540006dc989d6cf341d43464d241f84daccf889f47" nocase ascii wide
                        $string22_creddump7_offensive_tool_keyword = "4595ba305652431a89d142e09e6e5a9e67515bec0864017e8331082d3004611f" nocase ascii wide
                        $string23_creddump7_offensive_tool_keyword = "5a66c739cbd2e664a77e6dbbdcb318ca7a99e1a98e9314b0a90ea20378cdb9bd" nocase ascii wide
                        $string24_creddump7_offensive_tool_keyword = "960ad2b1c19c9d10ecd0c64f6aee01d77564ac9e48b76247a217b637c1a6d482" nocase ascii wide
                        $string25_creddump7_offensive_tool_keyword = "9f10e67d819156bec13f1a307df49dcf21bd91ddff45205818e402899e58ccca" nocase ascii wide
                        $string26_creddump7_offensive_tool_keyword = "ac4319f7349146fa891f608416dbf40475ebfdbbbec155939eb34d8fa1a67079" nocase ascii wide
                        $string27_creddump7_offensive_tool_keyword = "CiscoCXSecurity/creddump7" nocase ascii wide
                        $string28_creddump7_offensive_tool_keyword = "creddump7 -" nocase ascii wide
                        $string29_creddump7_offensive_tool_keyword = /creddump7\.exe/ nocase ascii wide
                        $string30_creddump7_offensive_tool_keyword = /creddump7\.win32\./ nocase ascii wide
                        $string31_creddump7_offensive_tool_keyword = /debian\.org\/pkg\-security\-team\/creddump7/ nocase ascii wide
                        $string32_creddump7_offensive_tool_keyword = "df8687a87b12b4cfcd9cad7082ed7c92bb43726b0d026aeeae6efd575539c0e8" nocase ascii wide
                        $string33_creddump7_offensive_tool_keyword = "eab9878a9916e998587cf5587e3ac5ce0e5509713b3afe6e64003e8c6962b565" nocase ascii wide
                        $string34_creddump7_offensive_tool_keyword = "f379a925c80b2f5959d3b3a0658895f7dad370b7478736a2957bc1ae2b59f14c" nocase ascii wide
                        $string35_creddump7_offensive_tool_keyword = /framework\.win32\.domcachedump/ nocase ascii wide
                        $string36_creddump7_offensive_tool_keyword = /framework\.win32\.lsasecrets/ nocase ascii wide
                        $string37_creddump7_offensive_tool_keyword = /https\:\/\/code\.google\.com\/p\/creddump\// nocase ascii wide
                        $string38_creddump7_offensive_tool_keyword = /pwdump\.py\sSYSTEM\sSAM/ nocase ascii wide
                        $string39_creddump7_offensive_tool_keyword = /usr\/share\/wordlists\/rockyou\.txt/ nocase ascii wide
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