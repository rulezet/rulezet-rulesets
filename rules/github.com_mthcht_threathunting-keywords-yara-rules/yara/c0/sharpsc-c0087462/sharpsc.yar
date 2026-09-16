rule SharpSC
{
    meta:
        description = "Detection patterns for the tool 'SharpSC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSC"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\saction\=create\s.{0,100}\sservice\=.{0,100}\sdisplayname\=.{0,100}\sbinpath\=/ nocase ascii wide
                        $string2 = /\/SharpSC\.exe/ nocase ascii wide
                        $string3 = /\/SharpSC\.git/ nocase ascii wide
                        $string4 = /\\SharpSC\.exe/ nocase ascii wide
                        $string5 = /\\SharpSC\-main/ nocase ascii wide
                        $string6 = "3b6a44069c343b15c9bafec9feb7d5597f936485c68f29316e96fe97aa15d06d" nocase ascii wide
                        $string7 = "3D9D679D-6052-4C5E-BD91-2BC3DED09D0A" nocase ascii wide
                        $string8 = "4c0fdf591ecec6aaeb3b6529f7b3800125910f16bc23496ba279a4bee0c2361c" nocase ascii wide
                        $string9 = "9870daa238c3cab7fa949a1f8b80d3451c78eb07d18030ad061d8b91d612decc" nocase ascii wide
                        $string10 = "djhohnstein/SharpSC" nocase ascii wide
                        $string11 = "namespace SharpSC" nocase ascii wide
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