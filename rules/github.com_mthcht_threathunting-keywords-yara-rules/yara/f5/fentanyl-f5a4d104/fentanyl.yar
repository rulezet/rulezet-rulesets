rule Fentanyl
{
    meta:
        description = "Detection patterns for the tool 'Fentanyl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fentanyl"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scursorinit\.vbs/ nocase ascii wide
                        $string2 = /\sfenty\.py/ nocase ascii wide
                        $string3 = /\\"N\/A\s\(Likely\sPirated\)\\"/ nocase ascii wide
                        $string4 = /\#\sForce\sAdmin\:\sBypass\sAdmin\sPrivileges\?/ nocase ascii wide
                        $string5 = /\#\sInject\:\sInject\spayload\sinto\sDiscord\?/ nocase ascii wide
                        $string6 = "# Injection URL: Raw URL to injection payload" nocase ascii wide
                        $string7 = /\/cursorinit\.vbs/ nocase ascii wide
                        $string8 = /\/Fentanyl\.git/ nocase ascii wide
                        $string9 = /\\fenty\.py/ nocase ascii wide
                        $string10 = /\\Roblox\sCookies\.txt/ nocase ascii wide
                        $string11 = /\{os\.getlogin\(\)\}\s\|\sFentanyl/ nocase ascii wide
                        $string12 = ">CursorSvc<" nocase ascii wide
                        $string13 = "2fa97965c5491fd73b586656a2a3d376013fa20918cc501f598439b85e49e244" nocase ascii wide
                        $string14 = "70376ae9437efcd92034825528cc12f1c0e03c1a4f965aabb3377d2a19e1d4f7" nocase ascii wide
                        $string15 = /bypassBetterDiscord\(/ nocase ascii wide
                        $string16 = /Cursors\\cursorinit\.vbs/ nocase ascii wide
                        $string17 = "dekrypted/Fentanyl" nocase ascii wide
                        $string18 = "Fentanyl strikes again!" nocase ascii wide
                        $string19 = /Fentanyl\/fenty\.py/ nocase ascii wide
                        $string20 = /findall\(r\\"dQw4w9WgXcQ/ nocase ascii wide
                        $string21 = /grabMinecraftCache\(/ nocase ascii wide
                        $string22 = /grabPasswords\(self\,mkp\,bname\,pname\,data\)/ nocase ascii wide
                        $string23 = /https\:\/\/.{0,1000}\.gofile\.io\/uploadFile/ nocase ascii wide
                        $string24 = /https\:\/\/cdn\.discordapp\.com\/attachments\/976805447266877471\/987826721250238464\/c33cd7baf5e2abdf434c2793988ccb56\.png/ nocase ascii wide
                        $string25 = /https\:\/\/github\.com\/dekrypted\// nocase ascii wide
                        $string26 = /https\:\/\/youareanidiot\.cc/ nocase ascii wide
                        $string27 = /if\sos\.getlogin\(\)\sin\s\[\\"WDAGUtilityAccount\\"\,\\"Abby\\"\,\\"Peter\sWilson\\"\,\\"hmarc\\"\,\\"patex\\"\,\\"JOHN\-PC\\"\,\\"RDhJ0CNFevzX\\"\,\\"kEecfMwgj\\"\,\\"Frank\\"\,\\"8Nl0ColNQ5bq\\"/ nocase ascii wide
                        $string28 = "reagentc /disable >nul" nocase ascii wide
                        $string29 = /reg\sadd\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\"\s\/v\s\\"SettingsPageVisibility\\"\s\/t\sREG_SZ\s\/d\s\\"hide\:recovery\;windowsdefender\\"\s\/f\s\>nul/ nocase ascii wide
                        $string30 = /REG\sADD\sHKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\s\/v\s\\"CursorInit\\"\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
                        $string31 = /REG\sADD\sHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\s\/v\s\\"CursorInit\\"\s\/t\sREG_SZ\s\/d\s/ nocase ascii wide
                        $string32 = "schtasks /create /tn \"CursorSvc\"" nocase ascii wide
                        $string33 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards" nocase ascii wide
                        $string34 = /\-\-Sharing\-this\-will\-allow\-someone\-to\-log\-in\-as\-you\-and\-to\-steal\-your\-ROBUX\-and\-items.{0,1000}decrypted_cookie/ nocase ascii wide
                        $string35 = "vssadmin delete shadows /all /quiet >nul" nocase ascii wide

    condition:
        any of them
}