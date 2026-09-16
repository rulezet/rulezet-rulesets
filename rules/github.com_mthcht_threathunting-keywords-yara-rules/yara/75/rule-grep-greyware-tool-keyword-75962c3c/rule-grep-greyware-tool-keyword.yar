rule rule_grep_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'grep' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "grep"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_grep_greyware_tool_keyword = /grep\s\-.{0,100}\s.{0,100}DBPassword/
                        $string2_grep_greyware_tool_keyword = /grep\s.{0,100}password\s\/var\/www/
                        $string3_grep_greyware_tool_keyword = /grep\s.{0,100}password\..{0,100}\s\/etc\/.{0,100}\.conf/
                        $string4_grep_greyware_tool_keyword = "grep :0: /etc/passwd"
                        $string5_grep_greyware_tool_keyword = "grep -i pass "
                        $string6_grep_greyware_tool_keyword = "grep -i user "
                        $string7_grep_greyware_tool_keyword = "grep -R db_passwd"
                        $string8_grep_greyware_tool_keyword = /grep\s\-roiE\s.{0,100}password/
                        $string9_grep_greyware_tool_keyword = /grep.{0,100}\|pwd\=\|passwd\=\|password\=/
                        $string10_grep_greyware_tool_keyword = /grep.{0,100}password\|pwd\|pass/
                        $string11_grep_greyware_tool_keyword = /strings\s\-n\s.{0,100}\s\/dev\/mem\s\|\sgrep\s\-i\spass/
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