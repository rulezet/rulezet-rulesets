rule WinPirate
{
    meta:
        description = "Detection patterns for the tool 'WinPirate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinPirate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " add nc without being detected by antivirus" nocase ascii wide
                        $string2 = /\schromepasswords\.py/ nocase ascii wide
                        $string3 = " stealthily grabs  passwords and browser history from windows systems" nocase ascii wide
                        $string4 = /\sStickykeys\.sh/ nocase ascii wide
                        $string5 = /\sWinPirate\.bat/ nocase ascii wide
                        $string6 = /\/browserhistory\.csv/ nocase ascii wide
                        $string7 = /\/chromepasswordlist\.csv/ nocase ascii wide
                        $string8 = /\/chromepasswords\.py/ nocase ascii wide
                        $string9 = /\/Stickykeys\.sh/ nocase ascii wide
                        $string10 = /\/WinPirate\.bat/ nocase ascii wide
                        $string11 = /\/WinPirate\.git/ nocase ascii wide
                        $string12 = /\\browserhistory\.csv/ nocase ascii wide
                        $string13 = /\\browsinghistoryview\\browsinghistoryview64\.exe/ nocase ascii wide
                        $string14 = /\\chromepasswordlist\.csv/ nocase ascii wide
                        $string15 = /\\chromepasswords\.py/ nocase ascii wide
                        $string16 = /\\Data\\WinAuditDB\.mdb/ nocase ascii wide
                        $string17 = /\\Invoke\-mimikittenz\.ps1/ nocase ascii wide
                        $string18 = /\\Stickykeys\.sh/ nocase ascii wide
                        $string19 = /\\Temp\\WinAuditDB\.accdb/ nocase ascii wide
                        $string20 = /\\WinAudit\.exe/ nocase ascii wide
                        $string21 = /\\WinPirate\.bat/ nocase ascii wide
                        $string22 = /\\WinPirate\\Tools\\/ nocase ascii wide
                        $string23 = /\\WinPirate\-master/ nocase ascii wide
                        $string24 = "14e2f70470396a18c27debb419a4f4063c2ad5b6976f429d47f55e31066a5e6a" nocase ascii wide
                        $string25 = "2033380cf345c3c743aefffe9e261457b23ececdb6ddd6ffe21436e6f71a8696" nocase ascii wide
                        $string26 = "2e7b0f4d6b446760a2899fcc2e854850014b3ce0826291913d3d3c160ed06191" nocase ascii wide
                        $string27 = "56f4763af00801c5eb80c39f141a563069669def9f98c1798c0f4b4094f34821" nocase ascii wide
                        $string28 = "906397a1765b82510679cb5b0f26ef1c8c89335c68f1d17178f924e5b2544454" nocase ascii wide
                        $string29 = "bfa3e36c356afe0742ffc32a3693257aacf59a671b07f695e31bd0f334fe0421" nocase ascii wide
                        $string30 = /Booty\\master_password_list\.csv/ nocase ascii wide
                        $string31 = /browsinghistoryview\.exe/ nocase ascii wide
                        $string32 = /BrowsingHistoryView\.html/ nocase ascii wide
                        $string33 = /c\:\\temp\\history\.csv/ nocase ascii wide
                        $string34 = /c\:\\temp\\history\.html/ nocase ascii wide
                        $string35 = /c\:\\temp\\history\.txt/ nocase ascii wide
                        $string36 = /cp\s\\"\/media\/windows\/Windows\/System32\/cmd\.exe\\"\s\\"\/media\/windows\/Windows\/System32\// nocase ascii wide
                        $string37 = "d4962bf59508b527bd83622e1f05a95e3f26f2d7583052744e3d8dcdd08c4556" nocase ascii wide
                        $string38 = "de09af73cc55f3dfbf6bf40493075b3c93765aa0ad88e34b568eac727f6b0c03" nocase ascii wide
                        $string39 = /drops\sa\snetcat\?\?\sundetectable\sby\santivirus/ nocase ascii wide
                        $string40 = /icacls\sc\:\\windows\\system32\\sethc\.exe/ nocase ascii wide
                        $string41 = "l3m0n/WinPirate" nocase ascii wide
                        $string42 = /mv\s\\"\/media\/windows\/Windows\/System32\/sethc\.exe\\"\s\\"\/media\/windows\/Windows\/System32\// nocase ascii wide
                        $string43 = "REM getting browser history" nocase ascii wide
                        $string44 = "REM wipe the logs" nocase ascii wide
                        $string45 = /ren\ssethc\.exe\ssethcbad\.exe/ nocase ascii wide
                        $string46 = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
                        $string47 = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
                        $string48 = /takeown\s\/f\sc\:\\windows\\system32\\sethc\.exe/ nocase ascii wide
                        $string49 = /takeown\s\/f\sc\:\\windows\\system32\\sethcold\.exe/ nocase ascii wide
                        $string50 = /Windows\/System32\/cmdlol\.exe/ nocase ascii wide
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