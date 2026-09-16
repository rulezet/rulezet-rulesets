rule rm
{
    meta:
        description = "Detection patterns for the tool 'rm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rm"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /rm\s\$HISTFILE/ nocase ascii wide
                        $string2 = /rm\s\.bash_history/
                        $string3 = "rm /var/log/"
                        $string4 = /rm\s\/var\/log\/.{0,100}\.log/
                        $string5 = /rm\s\~\/\.bash_history/
                        $string6 = /rm\s\-f\s.{0,100}\.bash_history/ nocase ascii wide
                        $string7 = /rm\s\-f\s.{0,100}\.zsh_history/ nocase ascii wide
                        $string8 = "rm -f /var/log/"
                        $string9 = /rm\s\-fr\s.{0,100}\.zsh_history/ nocase ascii wide
                        $string10 = "rm -r /var/log/"
                        $string11 = /rm\s\-rf\s.{0,100}\.zsh_history/ nocase ascii wide
                        $string12 = /rm\s\-rf\s\.bash_history/
                        $string13 = "rm -rf /var/log/"
                        $string14 = "rm -rf /var/log/messages"
                        $string15 = "rm -rf /var/log/security"
                        $string16 = /rm\s\-rf\s\~\/\.bash_history/
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