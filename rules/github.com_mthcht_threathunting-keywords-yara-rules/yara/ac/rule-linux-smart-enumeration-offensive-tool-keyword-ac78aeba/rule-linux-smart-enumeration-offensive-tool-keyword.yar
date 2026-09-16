rule rule_linux_smart_enumeration_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'linux-smart-enumeration' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-smart-enumeration"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_linux_smart_enumeration_offensive_tool_keyword = /\s\$lse_find_opts\s/
                        $string2_linux_smart_enumeration_offensive_tool_keyword = /\.\/lse\.sh/
                        $string3_linux_smart_enumeration_offensive_tool_keyword = /\/etc\/passwd.{0,100}\/\.sudo_as_admin_successful/
                        $string4_linux_smart_enumeration_offensive_tool_keyword = /\/linux\-smart\-enumeration\.git/
                        $string5_linux_smart_enumeration_offensive_tool_keyword = /\/releases\/latest\/download\/lse\.sh/
                        $string6_linux_smart_enumeration_offensive_tool_keyword = /adm\|admin\|root\|sudo\|wheel/
                        $string7_linux_smart_enumeration_offensive_tool_keyword = /bash\slse\.sh/
                        $string8_linux_smart_enumeration_offensive_tool_keyword = /chmod\s700\slse\.sh/
                        $string9_linux_smart_enumeration_offensive_tool_keyword = /chmod\s755\slse\.sh/
                        $string10_linux_smart_enumeration_offensive_tool_keyword = "diego-treitos/linux-smart-enumeration"
                        $string11_linux_smart_enumeration_offensive_tool_keyword = /find\s\/\s.{0,100}\s\-4000\s\-type\sf\s\-print/
                        $string12_linux_smart_enumeration_offensive_tool_keyword = /find\s\/\s.{0,100}\s\-perm\s\-2000\s\-type\sf\s\-print/
                        $string13_linux_smart_enumeration_offensive_tool_keyword = /find\s\/\s.{0,100}\s\-regextype\segrep\s\-iregex.{0,100}\\\.kdbx/
                        $string14_linux_smart_enumeration_offensive_tool_keyword = /https\:\/\/.{0,100}\/releases\/download\/.{0,100}\/lse\.sh/
                        $string15_linux_smart_enumeration_offensive_tool_keyword = "linux-smart-enumeration-master"
                        $string16_linux_smart_enumeration_offensive_tool_keyword = /lse\.sh\s\-l/
                        $string17_linux_smart_enumeration_offensive_tool_keyword = /netstat\s\-tnlp\s\|\|\sss\s\-tnlp/
                        $string18_linux_smart_enumeration_offensive_tool_keyword = /netstat\s\-unlp\s\|\|\sss\s\-unlp/
                        $string19_linux_smart_enumeration_offensive_tool_keyword = /package_cvs_into_lse\.sh/
                        $string20_linux_smart_enumeration_offensive_tool_keyword = /ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,100}127\.0\.0\.1/
                        $string21_linux_smart_enumeration_offensive_tool_keyword = "sudo -nS id' && lse_sudo=true"
                        $string22_linux_smart_enumeration_offensive_tool_keyword = /user\|username\|login\|pass\|password\|pw\|credentials/
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