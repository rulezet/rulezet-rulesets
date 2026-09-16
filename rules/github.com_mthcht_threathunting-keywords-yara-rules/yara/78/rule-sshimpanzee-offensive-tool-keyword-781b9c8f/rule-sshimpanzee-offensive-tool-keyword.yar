rule rule_sshimpanzee_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshimpanzee' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshimpanzee"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_sshimpanzee_offensive_tool_keyword = /\.\/sshimpanzee/
                        $string2_sshimpanzee_offensive_tool_keyword = /\/bin\/proxy_cli\.py/
                        $string3_sshimpanzee_offensive_tool_keyword = /\/sshimpanzee\.git/ nocase ascii wide
                        $string4_sshimpanzee_offensive_tool_keyword = /blog\.lexfo\.fr\/sshimpanzee\.html/ nocase ascii wide
                        $string5_sshimpanzee_offensive_tool_keyword = /dns\.lexfo\.fr/ nocase ascii wide
                        $string6_sshimpanzee_offensive_tool_keyword = /git\sreset\seb88d07c43afe407094e7d609248d85a15e148ef\s\-\-hard.{0,100}\srm\s\-f\ssshd/ nocase ascii wide
                        $string7_sshimpanzee_offensive_tool_keyword = "lexfo/sshimpanzee" nocase ascii wide
                        $string8_sshimpanzee_offensive_tool_keyword = /MODE\=.{0,100}\sREMOTE\=.{0,100}sshimpanzee/ nocase ascii wide
                        $string9_sshimpanzee_offensive_tool_keyword = /ProxyCommand\=nc\s\-lp\s8080\s\-s\s127\.0\.0\.1/ nocase ascii wide
                        $string10_sshimpanzee_offensive_tool_keyword = "sshimpanzee --" nocase ascii wide
                        $string11_sshimpanzee_offensive_tool_keyword = /sshimpanzee\:127\.0\.0\.1\:/ nocase ascii wide
                        $string12_sshimpanzee_offensive_tool_keyword = /sshimpanzee\-1\.1\-exp/ nocase ascii wide
                        $string13_sshimpanzee_offensive_tool_keyword = "sshimpanzee-main" nocase ascii wide
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