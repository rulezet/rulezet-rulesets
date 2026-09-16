rule rule_gobuster_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gobuster' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gobuster"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_gobuster_offensive_tool_keyword = /\/gobuster\.git/
                        $string2_gobuster_offensive_tool_keyword = "/gobuster/"
                        $string3_gobuster_offensive_tool_keyword = "/gobusterdir/"
                        $string4_gobuster_offensive_tool_keyword = "/gobusterdns/"
                        $string5_gobuster_offensive_tool_keyword = "/gobustergcs/"
                        $string6_gobuster_offensive_tool_keyword = "/libgobuster"
                        $string7_gobuster_offensive_tool_keyword = "/OJ/gobuster"
                        $string8_gobuster_offensive_tool_keyword = "gobuster dir "
                        $string9_gobuster_offensive_tool_keyword = "gobuster dns"
                        $string10_gobuster_offensive_tool_keyword = "gobuster fuzz -"
                        $string11_gobuster_offensive_tool_keyword = "gobuster gcs "
                        $string12_gobuster_offensive_tool_keyword = "gobuster s3 "
                        $string13_gobuster_offensive_tool_keyword = "gobuster tftp "
                        $string14_gobuster_offensive_tool_keyword = "gobuster vhost -u "
                        $string15_gobuster_offensive_tool_keyword = "gobuster vhost"
                        $string16_gobuster_offensive_tool_keyword = "gobuster"
                        $string17_gobuster_offensive_tool_keyword = /gobuster_.{0,100}\.tar\.gz/
                        $string18_gobuster_offensive_tool_keyword = /gobuster_.{0,100}\.zip/
                        $string19_gobuster_offensive_tool_keyword = "gobusterfuzz"
                        $string20_gobuster_offensive_tool_keyword = "gobustertftp"
                        $string21_gobuster_offensive_tool_keyword = "install gobuster"
                        $string22_gobuster_offensive_tool_keyword = /\-w\s.{0,100}wordlists.{0,100}\.txt/
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