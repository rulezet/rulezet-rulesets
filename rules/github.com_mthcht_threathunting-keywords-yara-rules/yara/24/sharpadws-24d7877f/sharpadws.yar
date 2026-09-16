rule SharpADWS
{
    meta:
        description = "Detection patterns for the tool 'SharpADWS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpADWS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scan\snow\simpersonate\susers\son\s.{0,100}\svia\sS4U2Proxy/ nocase ascii wide
                        $string2 = " Kerberoastable -action list" nocase ascii wide
                        $string3 = " Kerberoastable -action write -target " nocase ascii wide
                        $string4 = /\sRBCD\s\-action\swrite\s\-delegate\-to\s.{0,100}\s\-delegate\-from\s/ nocase ascii wide
                        $string5 = /\.exe\sacl\s\-dn\s.{0,100}\s\-scope\s.{0,100}\s\-trustee\s/ nocase ascii wide
                        $string6 = /\.exe\sCertify\s\-action\sfind\s\-enrolleeSuppliesSubject\s\-clientAuth/ nocase ascii wide
                        $string7 = /\.exe\sCertify\s\-action\sfind/ nocase ascii wide
                        $string8 = /\.exe\sDCSync\s\-action\slist/ nocase ascii wide
                        $string9 = /\.exe\sDCSync\s\-action\swrite\s\-target\s/ nocase ascii wide
                        $string10 = /\.exe\sDontReqPreAuth\s\-action\slist/ nocase ascii wide
                        $string11 = /\.exe\sDontReqPreAuth\s\-action\swrite\s\-target\s/ nocase ascii wide
                        $string12 = /\.exe\sRBCD\s\-action\sread\s\-delegate\-to\s/ nocase ascii wide
                        $string13 = /\.exe\sWhisker\s\-action\sadd\s\-target\s.{0,100}\s\-cert\-pass\s/ nocase ascii wide
                        $string14 = /\.exe\sWhisker\s\-action\slist\s\-target\s/ nocase ascii wide
                        $string15 = /\/SharpADWS\.git/ nocase ascii wide
                        $string16 = /\[\-\]\sAccount\sto\skerberoast\sdoes\snot\sexist\!/ nocase ascii wide
                        $string17 = /\[\-\]\sElevating\s.{0,100}\swith\sDCSync\sprivileges\sfailed/ nocase ascii wide
                        $string18 = /\\SharpADWS\.csproj/ nocase ascii wide
                        $string19 = /\\SharpADWS\.sln/ nocase ascii wide
                        $string20 = /\\SharpADWS\\/ nocase ascii wide
                        $string21 = /\\SharpADWS\-master/ nocase ascii wide
                        $string22 = /\]\sFound\skerberoastable\susers\:\s/ nocase ascii wide
                        $string23 = /\]\sKerberoast\suser\s.{0,100}\ssuccessfully\!/ nocase ascii wide
                        $string24 = "70ef0d3588b87bd71c2774c1bb177f59ae31a99b1a4ef82f7d2a16175c3caaf6" nocase ascii wide
                        $string25 = "AA488748-3D0E-4A52-8747-AB42A7143760" nocase ascii wide
                        $string26 = /SharpADWS\s1\.0\.0\-beta\s\-\sCopyright/ nocase ascii wide
                        $string27 = /SharpADWS\.exe/ nocase ascii wide
                        $string28 = "wh0amitz/SharpADWS" nocase ascii wide
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