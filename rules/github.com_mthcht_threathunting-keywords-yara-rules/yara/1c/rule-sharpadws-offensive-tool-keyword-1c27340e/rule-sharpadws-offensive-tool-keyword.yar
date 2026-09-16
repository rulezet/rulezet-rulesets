rule rule_SharpADWS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpADWS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpADWS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpADWS_offensive_tool_keyword = /\scan\snow\simpersonate\susers\son\s.{0,100}\svia\sS4U2Proxy/ nocase ascii wide
                        $string2_SharpADWS_offensive_tool_keyword = " Kerberoastable -action list" nocase ascii wide
                        $string3_SharpADWS_offensive_tool_keyword = " Kerberoastable -action write -target " nocase ascii wide
                        $string4_SharpADWS_offensive_tool_keyword = /\sRBCD\s\-action\swrite\s\-delegate\-to\s.{0,100}\s\-delegate\-from\s/ nocase ascii wide
                        $string5_SharpADWS_offensive_tool_keyword = /\.exe\sacl\s\-dn\s.{0,100}\s\-scope\s.{0,100}\s\-trustee\s/ nocase ascii wide
                        $string6_SharpADWS_offensive_tool_keyword = /\.exe\sCertify\s\-action\sfind\s\-enrolleeSuppliesSubject\s\-clientAuth/ nocase ascii wide
                        $string7_SharpADWS_offensive_tool_keyword = /\.exe\sCertify\s\-action\sfind/ nocase ascii wide
                        $string8_SharpADWS_offensive_tool_keyword = /\.exe\sDCSync\s\-action\slist/ nocase ascii wide
                        $string9_SharpADWS_offensive_tool_keyword = /\.exe\sDCSync\s\-action\swrite\s\-target\s/ nocase ascii wide
                        $string10_SharpADWS_offensive_tool_keyword = /\.exe\sDontReqPreAuth\s\-action\slist/ nocase ascii wide
                        $string11_SharpADWS_offensive_tool_keyword = /\.exe\sDontReqPreAuth\s\-action\swrite\s\-target\s/ nocase ascii wide
                        $string12_SharpADWS_offensive_tool_keyword = /\.exe\sRBCD\s\-action\sread\s\-delegate\-to\s/ nocase ascii wide
                        $string13_SharpADWS_offensive_tool_keyword = /\.exe\sWhisker\s\-action\sadd\s\-target\s.{0,100}\s\-cert\-pass\s/ nocase ascii wide
                        $string14_SharpADWS_offensive_tool_keyword = /\.exe\sWhisker\s\-action\slist\s\-target\s/ nocase ascii wide
                        $string15_SharpADWS_offensive_tool_keyword = /\/SharpADWS\.git/ nocase ascii wide
                        $string16_SharpADWS_offensive_tool_keyword = /\[\-\]\sAccount\sto\skerberoast\sdoes\snot\sexist\!/ nocase ascii wide
                        $string17_SharpADWS_offensive_tool_keyword = /\[\-\]\sElevating\s.{0,100}\swith\sDCSync\sprivileges\sfailed/ nocase ascii wide
                        $string18_SharpADWS_offensive_tool_keyword = /\\SharpADWS\.csproj/ nocase ascii wide
                        $string19_SharpADWS_offensive_tool_keyword = /\\SharpADWS\.sln/ nocase ascii wide
                        $string20_SharpADWS_offensive_tool_keyword = /\\SharpADWS\\/ nocase ascii wide
                        $string21_SharpADWS_offensive_tool_keyword = /\\SharpADWS\-master/ nocase ascii wide
                        $string22_SharpADWS_offensive_tool_keyword = /\]\sFound\skerberoastable\susers\:\s/ nocase ascii wide
                        $string23_SharpADWS_offensive_tool_keyword = /\]\sKerberoast\suser\s.{0,100}\ssuccessfully\!/ nocase ascii wide
                        $string24_SharpADWS_offensive_tool_keyword = "70ef0d3588b87bd71c2774c1bb177f59ae31a99b1a4ef82f7d2a16175c3caaf6" nocase ascii wide
                        $string25_SharpADWS_offensive_tool_keyword = "AA488748-3D0E-4A52-8747-AB42A7143760" nocase ascii wide
                        $string26_SharpADWS_offensive_tool_keyword = /SharpADWS\s1\.0\.0\-beta\s\-\sCopyright/ nocase ascii wide
                        $string27_SharpADWS_offensive_tool_keyword = /SharpADWS\.exe/ nocase ascii wide
                        $string28_SharpADWS_offensive_tool_keyword = "wh0amitz/SharpADWS" nocase ascii wide
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