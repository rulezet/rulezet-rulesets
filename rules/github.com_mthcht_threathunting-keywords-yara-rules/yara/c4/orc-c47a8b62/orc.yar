rule Orc
{
    meta:
        description = "Detection patterns for the tool 'Orc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Orc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\smemexec\.pl/
                        $string2 = /\smemexec\.py/
                        $string3 = "#god bless you, NSA's autorootkit"
                        $string4 = /\/memexec\.pl/
                        $string5 = /\/memexec\.py/
                        $string6 = /\/suspect\/master\/suspect\.sh/
                        $string7 = "= Welcome to Orc Shell ="
                        $string8 = "50084b701b0463d1698211f2d0427c3eb6322be963c46cf9a4eb39e01a94cddc"
                        $string9 = "810b9f7c517f7f00516340661ecaf5610b89ea25ff5261964abe067a40c474c2"
                        $string10 = "find /tmp/ -executable -type f 2>/dev/null"
                        $string11 = "find /var/tmp -executable -type f 2>/dev/null"
                        $string12 = /getent\spasswd\s\|\sgrep\ssh\$\s\|\scut\s\-d\s/
                        $string13 = /linux\-exploit\-suggester\.sh/
                        $string14 = "lsattr -a /usr/bin/ /bin/ /sbin/ /usr/sbin/ 2>/dev/null"
                        $string15 = /orc_loadURL\s\'https\:\/\/gtfobins\.github\.io/
                        $string16 = "zMarch/Orc"
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