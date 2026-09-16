rule rule_RDE1_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RDE1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDE1"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RDE1_offensive_tool_keyword = " crde_arm_musl https -" nocase ascii wide
                        $string2_RDE1_offensive_tool_keyword = " crde_armv7 https -" nocase ascii wide
                        $string3_RDE1_offensive_tool_keyword = " crde_debug https -" nocase ascii wide
                        $string4_RDE1_offensive_tool_keyword = " crde_linux https -"
                        $string5_RDE1_offensive_tool_keyword = " crde_linux_aarch64 https -"
                        $string6_RDE1_offensive_tool_keyword = " crde_linux_x86_64 https -"
                        $string7_RDE1_offensive_tool_keyword = " crde_macos https -" nocase ascii wide
                        $string8_RDE1_offensive_tool_keyword = " crde_release https -" nocase ascii wide
                        $string9_RDE1_offensive_tool_keyword = " crde_windows https -" nocase ascii wide
                        $string10_RDE1_offensive_tool_keyword = " crde_windows_x64 https -" nocase ascii wide
                        $string11_RDE1_offensive_tool_keyword = " crde_windows_x86 https -" nocase ascii wide
                        $string12_RDE1_offensive_tool_keyword = /\shttps\s\-i\s0\.0\.0\.0\s\-P\s.{0,100}\s\-k\s.{0,100}\s\-\-private\-cert\s.{0,100}\s\-\-public\-cert\s/ nocase ascii wide
                        $string13_RDE1_offensive_tool_keyword = " rde1 crde_windows" nocase ascii wide
                        $string14_RDE1_offensive_tool_keyword = " rde1 srde_linux"
                        $string15_RDE1_offensive_tool_keyword = " rde1 srde_macos" nocase ascii wide
                        $string16_RDE1_offensive_tool_keyword = " rde1 srde_windows" nocase ascii wide
                        $string17_RDE1_offensive_tool_keyword = " rec2 crde_linux"
                        $string18_RDE1_offensive_tool_keyword = " rec2 crde_macos" nocase ascii wide
                        $string19_RDE1_offensive_tool_keyword = " srde_arm_musl https -" nocase ascii wide
                        $string20_RDE1_offensive_tool_keyword = " srde_armv7 https -" nocase ascii wide
                        $string21_RDE1_offensive_tool_keyword = " srde_debug https -" nocase ascii wide
                        $string22_RDE1_offensive_tool_keyword = " srde_linux https -"
                        $string23_RDE1_offensive_tool_keyword = " srde_linux_aarch64 https -"
                        $string24_RDE1_offensive_tool_keyword = " srde_linux_x86_64 https -"
                        $string25_RDE1_offensive_tool_keyword = " srde_macos https -" nocase ascii wide
                        $string26_RDE1_offensive_tool_keyword = " srde_release https -" nocase ascii wide
                        $string27_RDE1_offensive_tool_keyword = " srde_windows https -" nocase ascii wide
                        $string28_RDE1_offensive_tool_keyword = " srde_windows_x64 https -" nocase ascii wide
                        $string29_RDE1_offensive_tool_keyword = " srde_windows_x86 https -" nocase ascii wide
                        $string30_RDE1_offensive_tool_keyword = /\/RDE1\.git/ nocase ascii wide
                        $string31_RDE1_offensive_tool_keyword = "crde dns -" nocase ascii wide
                        $string32_RDE1_offensive_tool_keyword = "crde https -" nocase ascii wide
                        $string33_RDE1_offensive_tool_keyword = "crde::utils::checker" nocase ascii wide
                        $string34_RDE1_offensive_tool_keyword = /crde_x64\.exe\sdns\s\-f\s/ nocase ascii wide
                        $string35_RDE1_offensive_tool_keyword = /crde_x64\.exe\shttps\s\-f\s/ nocase ascii wide
                        $string36_RDE1_offensive_tool_keyword = /docker\srun\s.{0,100}\/usr\/src\/rde1/ nocase ascii wide
                        $string37_RDE1_offensive_tool_keyword = /docker\srun\s.{0,100}\/usr\/src\/rec2/ nocase ascii wide
                        $string38_RDE1_offensive_tool_keyword = "Exfiltration from DNS finished!" nocase ascii wide
                        $string39_RDE1_offensive_tool_keyword = "Exfiltration from HTTPS finished!" nocase ascii wide
                        $string40_RDE1_offensive_tool_keyword = "g0h4n/RDE1" nocase ascii wide
                        $string41_RDE1_offensive_tool_keyword = "methods::dns::dns_exfiltrator" nocase ascii wide
                        $string42_RDE1_offensive_tool_keyword = "methods::https::https_exfiltrator" nocase ascii wide
                        $string43_RDE1_offensive_tool_keyword = "methods::icmp::icmp_exfiltrator" nocase ascii wide
                        $string44_RDE1_offensive_tool_keyword = /RDE1\-main\.zip/ nocase ascii wide
                        $string45_RDE1_offensive_tool_keyword = "srde dns -" nocase ascii wide
                        $string46_RDE1_offensive_tool_keyword = "srde https -" nocase ascii wide
                        $string47_RDE1_offensive_tool_keyword = "srde_release dns -k " nocase ascii wide
                        $string48_RDE1_offensive_tool_keyword = "srde_release https -i " nocase ascii wide
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