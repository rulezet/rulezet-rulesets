rule rustcat
{
    meta:
        description = "Detection patterns for the tool 'rustcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rustcat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1\'/
                        $string2 = /\/rcat\-v.{0,100}\-win\-x86_64\.exe/ nocase ascii wide
                        $string3 = "/rustcat/releases/latest/download/" nocase ascii wide
                        $string4 = /\/src\/unixshell\.rs/ nocase ascii wide
                        $string5 = /\\rcat\-v.{0,100}\-win\-x86_64\.exe/ nocase ascii wide
                        $string6 = "B473B9A4135DE247C6D76510B40F63F8F1E5A2AB" nocase ascii wide
                        $string7 = "blackarch/tree/master/packages/rustcat" nocase ascii wide
                        $string8 = "pacman -S rustcat" nocase ascii wide
                        $string9 = "rcan listen -ib " nocase ascii wide
                        $string10 = "rcat c -s bash "
                        $string11 = "rcat connect -s bash"
                        $string12 = "rcat listen 55660" nocase ascii wide
                        $string13 = "rcat listen -ie " nocase ascii wide
                        $string14 = "rcat listen -l " nocase ascii wide
                        $string15 = /rcat\-v3\..{0,100}darwin\-aarch64/
                        $string16 = /rcat\-v3\..{0,100}\-darwin\-x86_64/
                        $string17 = /rcat\-v3\..{0,100}\-linux\-x86_64/
                        $string18 = /rustcat\-3\.0\.0\.zip/ nocase ascii wide
                        $string19 = "rcat listen " nocase ascii wide
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