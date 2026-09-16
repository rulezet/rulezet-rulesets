rule Stompy
{
    meta:
        description = "Detection patterns for the tool 'Stompy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stompy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sStompy\.ps1/ nocase ascii wide
                        $string2 = /\sStomPY\.py\s/ nocase ascii wide
                        $string3 = /\.\/GoStompy\s/
                        $string4 = /\.exe.{0,100}\s\-path\s.{0,100}\s\-newTimestamp\s.{0,100}\s\-username\s.{0,100}\s\-password\s/ nocase ascii wide
                        $string5 = /\/GoStompy\.go/ nocase ascii wide
                        $string6 = /\/Stompy\.git/ nocase ascii wide
                        $string7 = /\/Stompy\.ps1/ nocase ascii wide
                        $string8 = /\/StomPY\.py/ nocase ascii wide
                        $string9 = /\\GoStompy\.go/ nocase ascii wide
                        $string10 = /\\Stompy\.ps1/ nocase ascii wide
                        $string11 = /\\StomPY\.py/ nocase ascii wide
                        $string12 = /\\Stompy\-main\\/ nocase ascii wide
                        $string13 = "784F8029-4D72-4363-9638-5A8D11545494" nocase ascii wide
                        $string14 = /build\sGoStompy\.go/ nocase ascii wide
                        $string15 = "Invoke-Stompy" nocase ascii wide
                        $string16 = /StompySharps\.csproj/ nocase ascii wide
                        $string17 = /StompySharps\.exe/ nocase ascii wide
                        $string18 = /StompySharps\.sln/ nocase ascii wide
                        $string19 = "ZephrFish/Stompy" nocase ascii wide
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