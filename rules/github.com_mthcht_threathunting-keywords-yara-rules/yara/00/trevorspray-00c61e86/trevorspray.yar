rule TREVORspray
{
    meta:
        description = "Detection patterns for the tool 'TREVORspray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TREVORspray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/TREVORspray\.git/ nocase ascii wide
                        $string2 = /\/trevorspray\.log/ nocase ascii wide
                        $string3 = /\/tried_logins\.txt/
                        $string4 = "blacklanternsecurity/trevorproxy" nocase ascii wide
                        $string5 = "blacklanternsecurity/TREVORspray" nocase ascii wide
                        $string6 = "import BaseSprayModule" nocase ascii wide
                        $string7 = /spray.{0,100}\s\-\-recon\s.{0,100}\..{0,100}\s\-u\s.{0,100}\.txt\s\-\-threads\s10/ nocase ascii wide
                        $string8 = "TlRMTVNTUAABAAAABYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAA" nocase ascii wide
                        $string9 = "trevorproxy ssh" nocase ascii wide
                        $string10 = "trevorproxy subnet" nocase ascii wide
                        $string11 = "trevorspray -" nocase ascii wide
                        $string12 = /trevorspray\.cli/ nocase ascii wide
                        $string13 = /trevorspray\.enumerators/ nocase ascii wide
                        $string14 = /trevorspray\.looters/ nocase ascii wide
                        $string15 = /trevorspray\.py/ nocase ascii wide
                        $string16 = /trevorspray\.sprayers/ nocase ascii wide
                        $string17 = /trevorspray\/existent_users\.txt/ nocase ascii wide
                        $string18 = /trevorspray\/valid_logins\.txt/ nocase ascii wide
                        $string19 = "TREVORspray-dev" nocase ascii wide
                        $string20 = "TREVORspray-master" nocase ascii wide
                        $string21 = "TREVORspray-trevorspray" nocase ascii wide
                        $string22 = "Your Moms Smart Vibrator" nocase ascii wide
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