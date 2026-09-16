rule rule_cheetah_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cheetah' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cheetah"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cheetah_offensive_tool_keyword = /\s\-p\spwd1\.list\spwd2\.list\s/ nocase ascii wide
                        $string2_cheetah_offensive_tool_keyword = /\/big_shell_pwd\.7z/ nocase ascii wide
                        $string3_cheetah_offensive_tool_keyword = /\/cheetah\.git/ nocase ascii wide
                        $string4_cheetah_offensive_tool_keyword = /\/cheetah\.py/
                        $string5_cheetah_offensive_tool_keyword = /\\big_shell_pwd\.7z/ nocase ascii wide
                        $string6_cheetah_offensive_tool_keyword = /\\cheetah\.py/ nocase ascii wide
                        $string7_cheetah_offensive_tool_keyword = /\\cheetah\-master\.zip/ nocase ascii wide
                        $string8_cheetah_offensive_tool_keyword = "5a1f9b0e-9f7c-4673-bf16-4740707f41b7" nocase ascii wide
                        $string9_cheetah_offensive_tool_keyword = /a\svery\sfast\sbrute\sforce\swebshell\spassword\stool\./ nocase ascii wide
                        $string10_cheetah_offensive_tool_keyword = /cheetah\.py\s\-/ nocase ascii wide
                        $string11_cheetah_offensive_tool_keyword = /git\sclone\s.{0,100}\s\/tmp\/cheetah/ nocase ascii wide
                        $string12_cheetah_offensive_tool_keyword = /http\:\/\/localhost\/shell\.jsp\?pwd\=System\.out\.println\(/ nocase ascii wide
                        $string13_cheetah_offensive_tool_keyword = "run --rm -it xshuden/cheetah" nocase ascii wide
                        $string14_cheetah_offensive_tool_keyword = "shmilylty/cheetah" nocase ascii wide
                        $string15_cheetah_offensive_tool_keyword = /sunnyelf\/cheetah\/archive\/master\.zip/ nocase ascii wide
                        $string16_cheetah_offensive_tool_keyword = /sunnyelf\[\@hackfun\.org\]/ nocase ascii wide
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