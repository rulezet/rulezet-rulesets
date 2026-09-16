rule SharpSpray
{
    meta:
        description = "Detection patterns for the tool 'SharpSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-o\ssprayed\.txt/ nocase ascii wide
                        $string2 = /\ssharpspray\.exe/ nocase ascii wide
                        $string3 = " -x -z --get-users-list" nocase ascii wide
                        $string4 = /\s\-x\s\-z\s\-s\s3\s\-j\s1\s\-u\s.{0,100}\.txt/ nocase ascii wide
                        $string5 = /\.exe\s\-\-get\-users\-list\s\>\s/ nocase ascii wide
                        $string6 = /\/sharpspray\.exe/ nocase ascii wide
                        $string7 = /\/SharpSpray\.git/ nocase ascii wide
                        $string8 = /\/SharpSpray\-1\.1\.zip/ nocase ascii wide
                        $string9 = /\\SharpSpray\.csproj/ nocase ascii wide
                        $string10 = /\\sharpspray\.exe/ nocase ascii wide
                        $string11 = /\\SharpSpray\.sln/ nocase ascii wide
                        $string12 = /\\SharpSpray\\/ nocase ascii wide
                        $string13 = /\\SharpSpray\-1\.1\.zip/ nocase ascii wide
                        $string14 = "29CFAA16-9277-4EFB-9E91-A7D11225160B" nocase ascii wide
                        $string15 = "9a30590136ad955b56d367ca00f3d9feb50d4a3fb1d643fc8e3bb3cbcfd1dfa1" nocase ascii wide
                        $string16 = /DomainPasswordSpray\.ps1/ nocase ascii wide
                        $string17 = "iomoath/SharpSpray" nocase ascii wide
                        $string18 = "SharpSpray" nocase ascii wide
                        $string19 = /SharpSpray\\Program\.cs/ nocase ascii wide
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