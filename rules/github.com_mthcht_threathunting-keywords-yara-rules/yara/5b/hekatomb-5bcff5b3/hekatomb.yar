rule HEKATOMB
{
    meta:
        description = "Detection patterns for the tool 'HEKATOMB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HEKATOMB"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install hekatomb" nocase ascii wide
                        $string2 = /\.py\s.{0,100}\s\-debug\s\-dnstcp/ nocase ascii wide
                        $string3 = /\/exported_credentials\.csv/
                        $string4 = /\[\+\]\sConnnecting\sto\sall\scomputers\sand\stry\sto\sget\sdpapi\sblobs\sand\smaster\skey\sfiles/ nocase ascii wide
                        $string5 = /\[\+\]\sScanning\scomputers\slist\son\sSMB\sport\s/ nocase ascii wide
                        $string6 = /\\exported_credentials\.csv/ nocase ascii wide
                        $string7 = "ed9d3ee993fe0a36bb7a7fce3940112ea29eccca58165738a758c58a3fe0ae54" nocase ascii wide
                        $string8 = "hekatomb -hashes " nocase ascii wide
                        $string9 = /hekatomb\-.{0,100}\.tar\.gz/ nocase ascii wide
                        $string10 = /hekatomb.{0,100}\-hashes\s/ nocase ascii wide
                        $string11 = /hekatomb\-.{0,100}\-py3\-none\-any\.whl/ nocase ascii wide
                        $string12 = /hekatomb\.ad_ldap/ nocase ascii wide
                        $string13 = /hekatomb\@thiefin\.fr/ nocase ascii wide
                        $string14 = "it will extract domain controller private key through RPC uses it to decrypt all credentials" nocase ascii wide
                        $string15 = /New\scredentials\sfound\sfor\suser\s.{0,100}\son\s/ nocase ascii wide
                        $string16 = "pacman -S hekatomb" nocase ascii wide
                        $string17 = "poetry run hekatomb" nocase ascii wide
                        $string18 = "Processus-Thief/HEKATOMB" nocase ascii wide
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