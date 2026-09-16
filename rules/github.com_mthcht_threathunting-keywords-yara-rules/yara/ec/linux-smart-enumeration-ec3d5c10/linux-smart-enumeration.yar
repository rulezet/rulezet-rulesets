rule linux_smart_enumeration
{
    meta:
        description = "Detection patterns for the tool 'linux-smart-enumeration' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-smart-enumeration"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\$lse_find_opts\s/
                        $string2 = /\.\/lse\.sh/
                        $string3 = /\/etc\/passwd.{0,100}\/\.sudo_as_admin_successful/
                        $string4 = /\/linux\-smart\-enumeration\.git/
                        $string5 = /\/releases\/latest\/download\/lse\.sh/
                        $string6 = /adm\|admin\|root\|sudo\|wheel/
                        $string7 = /bash\slse\.sh/
                        $string8 = /chmod\s700\slse\.sh/
                        $string9 = /chmod\s755\slse\.sh/
                        $string10 = "diego-treitos/linux-smart-enumeration"
                        $string11 = /find\s\/\s.{0,100}\s\-4000\s\-type\sf\s\-print/
                        $string12 = /find\s\/\s.{0,100}\s\-perm\s\-2000\s\-type\sf\s\-print/
                        $string13 = /find\s\/\s.{0,100}\s\-regextype\segrep\s\-iregex.{0,100}\\\.kdbx/
                        $string14 = /https\:\/\/.{0,100}\/releases\/download\/.{0,100}\/lse\.sh/
                        $string15 = "linux-smart-enumeration-master"
                        $string16 = /lse\.sh\s\-l/
                        $string17 = /netstat\s\-tnlp\s\|\|\sss\s\-tnlp/
                        $string18 = /netstat\s\-unlp\s\|\|\sss\s\-unlp/
                        $string19 = /package_cvs_into_lse\.sh/
                        $string20 = /ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,100}127\.0\.0\.1/
                        $string21 = "sudo -nS id' && lse_sudo=true"
                        $string22 = /user\|username\|login\|pass\|password\|pw\|credentials/
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