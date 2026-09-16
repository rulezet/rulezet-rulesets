rule rule_Fentanyl_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Fentanyl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fentanyl"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Fentanyl_offensive_tool_keyword = /\scursorinit\.vbs/ nocase ascii wide
                        $string2_Fentanyl_offensive_tool_keyword = /\sfenty\.py/ nocase ascii wide
                        $string3_Fentanyl_offensive_tool_keyword = /\\"N\/A\s\(Likely\sPirated\)\\"/ nocase ascii wide
                        $string4_Fentanyl_offensive_tool_keyword = /\#\sForce\sAdmin\:\sBypass\sAdmin\sPrivileges\?/ nocase ascii wide
                        $string5_Fentanyl_offensive_tool_keyword = /\#\sInject\:\sInject\spayload\sinto\sDiscord\?/ nocase ascii wide
                        $string6_Fentanyl_offensive_tool_keyword = "# Injection URL: Raw URL to injection payload" nocase ascii wide
                        $string7_Fentanyl_offensive_tool_keyword = /\/cursorinit\.vbs/ nocase ascii wide
                        $string8_Fentanyl_offensive_tool_keyword = /\/Fentanyl\.git/ nocase ascii wide
                        $string9_Fentanyl_offensive_tool_keyword = /\\fenty\.py/ nocase ascii wide
                        $string10_Fentanyl_offensive_tool_keyword = /\\Roblox\sCookies\.txt/ nocase ascii wide
                        $string11_Fentanyl_offensive_tool_keyword = /\{os\.getlogin\(\)\}\s\|\sFentanyl/ nocase ascii wide
                        $string12_Fentanyl_offensive_tool_keyword = ">CursorSvc<" nocase ascii wide
                        $string13_Fentanyl_offensive_tool_keyword = "2fa97965c5491fd73b586656a2a3d376013fa20918cc501f598439b85e49e244" nocase ascii wide
                        $string14_Fentanyl_offensive_tool_keyword = "70376ae9437efcd92034825528cc12f1c0e03c1a4f965aabb3377d2a19e1d4f7" nocase ascii wide
                        $string15_Fentanyl_offensive_tool_keyword = /bypassBetterDiscord\(/ nocase ascii wide
                        $string16_Fentanyl_offensive_tool_keyword = /Cursors\\cursorinit\.vbs/ nocase ascii wide
                        $string17_Fentanyl_offensive_tool_keyword = "dekrypted/Fentanyl" nocase ascii wide
                        $string18_Fentanyl_offensive_tool_keyword = "Fentanyl strikes again!" nocase ascii wide
                        $string19_Fentanyl_offensive_tool_keyword = /Fentanyl\/fenty\.py/ nocase ascii wide
                        $string20_Fentanyl_offensive_tool_keyword = /findall\(r\\"dQw4w9WgXcQ/ nocase ascii wide
                        $string21_Fentanyl_offensive_tool_keyword = /grabMinecraftCache\(/ nocase ascii wide
                        $string22_Fentanyl_offensive_tool_keyword = /grabPasswords\(self\,mkp\,bname\,pname\,data\)/ nocase ascii wide
                        $string23_Fentanyl_offensive_tool_keyword = /https\:\/\/.{0,100}\.gofile\.io\/uploadFile/ nocase ascii wide
                        $string24_Fentanyl_offensive_tool_keyword = /https\:\/\/cdn\.discordapp\.com\/attachments\/976805447266877471\/987826721250238464\/c33cd7baf5e2abdf434c2793988ccb56\.png/ nocase ascii wide
                        $string25_Fentanyl_offensive_tool_keyword = /https\:\/\/github\.com\/dekrypted\// nocase ascii wide
                        $string26_Fentanyl_offensive_tool_keyword = /https\:\/\/youareanidiot\.cc/ nocase ascii wide
                        $string27_Fentanyl_offensive_tool_keyword = /if\sos\.getlogin\(\)\sin\s\[\\"WDAGUtilityAccount\\"\,\\"Abby\\"\,\\"Peter\sWilson\\"\,\\"hmarc\\"\,\\"patex\\"\,\\"JOHN\-PC\\"\,\\"RDhJ0CNFevzX\\"\,\\"kEecfMwgj\\"\,\\"Frank\\"\,\\"8Nl0ColNQ5bq\\"/ nocase ascii wide
                        $string28_Fentanyl_offensive_tool_keyword = "reagentc /disable >nul" nocase ascii wide
                        $string29_Fentanyl_offensive_tool_keyword = /reg\sadd\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\"\s\/v\s\\"SettingsPageVisibility\\"\s\/t\sREG_SZ\s\/d\s\\"hide\:recovery\;windowsdefender\\"\s\/f\s\>nul/ nocase ascii wide
                        $string30_Fentanyl_offensive_tool_keyword = /REG\sADD\sHKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\s\/v\s\\"CursorInit\\"\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
                        $string31_Fentanyl_offensive_tool_keyword = /REG\sADD\sHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\s\/v\s\\"CursorInit\\"\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
                        $string32_Fentanyl_offensive_tool_keyword = "schtasks /create /tn \"CursorSvc\"" nocase ascii wide
                        $string33_Fentanyl_offensive_tool_keyword = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" nocase ascii wide
                        $string34_Fentanyl_offensive_tool_keyword = /\-\-Sharing\-this\-will\-allow\-someone\-to\-log\-in\-as\-you\-and\-to\-steal\-your\-ROBUX\-and\-items.{0,100}decrypted_cookie/ nocase ascii wide
                        $string35_Fentanyl_offensive_tool_keyword = "vssadmin delete shadows /all /quiet >nul" nocase ascii wide
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