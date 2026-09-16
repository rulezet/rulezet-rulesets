rule rule_WinPirate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WinPirate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinPirate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WinPirate_offensive_tool_keyword = " add nc without being detected by antivirus" nocase ascii wide
                        $string2_WinPirate_offensive_tool_keyword = /\schromepasswords\.py/ nocase ascii wide
                        $string3_WinPirate_offensive_tool_keyword = " stealthily grabs  passwords and browser history from windows systems" nocase ascii wide
                        $string4_WinPirate_offensive_tool_keyword = /\sStickykeys\.sh/ nocase ascii wide
                        $string5_WinPirate_offensive_tool_keyword = /\sWinPirate\.bat/ nocase ascii wide
                        $string6_WinPirate_offensive_tool_keyword = /\/browserhistory\.csv/ nocase ascii wide
                        $string7_WinPirate_offensive_tool_keyword = /\/chromepasswordlist\.csv/ nocase ascii wide
                        $string8_WinPirate_offensive_tool_keyword = /\/chromepasswords\.py/ nocase ascii wide
                        $string9_WinPirate_offensive_tool_keyword = /\/Stickykeys\.sh/ nocase ascii wide
                        $string10_WinPirate_offensive_tool_keyword = /\/WinPirate\.bat/ nocase ascii wide
                        $string11_WinPirate_offensive_tool_keyword = /\/WinPirate\.git/ nocase ascii wide
                        $string12_WinPirate_offensive_tool_keyword = /\\browserhistory\.csv/ nocase ascii wide
                        $string13_WinPirate_offensive_tool_keyword = /\\browsinghistoryview\\browsinghistoryview64\.exe/ nocase ascii wide
                        $string14_WinPirate_offensive_tool_keyword = /\\chromepasswordlist\.csv/ nocase ascii wide
                        $string15_WinPirate_offensive_tool_keyword = /\\chromepasswords\.py/ nocase ascii wide
                        $string16_WinPirate_offensive_tool_keyword = /\\Data\\WinAuditDB\.mdb/ nocase ascii wide
                        $string17_WinPirate_offensive_tool_keyword = /\\Invoke\-mimikittenz\.ps1/ nocase ascii wide
                        $string18_WinPirate_offensive_tool_keyword = /\\Stickykeys\.sh/ nocase ascii wide
                        $string19_WinPirate_offensive_tool_keyword = /\\Temp\\WinAuditDB\.accdb/ nocase ascii wide
                        $string20_WinPirate_offensive_tool_keyword = /\\WinAudit\.exe/ nocase ascii wide
                        $string21_WinPirate_offensive_tool_keyword = /\\WinPirate\.bat/ nocase ascii wide
                        $string22_WinPirate_offensive_tool_keyword = /\\WinPirate\\Tools\\/ nocase ascii wide
                        $string23_WinPirate_offensive_tool_keyword = /\\WinPirate\-master/ nocase ascii wide
                        $string24_WinPirate_offensive_tool_keyword = "14e2f70470396a18c27debb419a4f4063c2ad5b6976f429d47f55e31066a5e6a" nocase ascii wide
                        $string25_WinPirate_offensive_tool_keyword = "2033380cf345c3c743aefffe9e261457b23ececdb6ddd6ffe21436e6f71a8696" nocase ascii wide
                        $string26_WinPirate_offensive_tool_keyword = "2e7b0f4d6b446760a2899fcc2e854850014b3ce0826291913d3d3c160ed06191" nocase ascii wide
                        $string27_WinPirate_offensive_tool_keyword = "56f4763af00801c5eb80c39f141a563069669def9f98c1798c0f4b4094f34821" nocase ascii wide
                        $string28_WinPirate_offensive_tool_keyword = "906397a1765b82510679cb5b0f26ef1c8c89335c68f1d17178f924e5b2544454" nocase ascii wide
                        $string29_WinPirate_offensive_tool_keyword = "bfa3e36c356afe0742ffc32a3693257aacf59a671b07f695e31bd0f334fe0421" nocase ascii wide
                        $string30_WinPirate_offensive_tool_keyword = /Booty\\master_password_list\.csv/ nocase ascii wide
                        $string31_WinPirate_offensive_tool_keyword = /browsinghistoryview\.exe/ nocase ascii wide
                        $string32_WinPirate_offensive_tool_keyword = /BrowsingHistoryView\.html/ nocase ascii wide
                        $string33_WinPirate_offensive_tool_keyword = /c\:\\temp\\history\.csv/ nocase ascii wide
                        $string34_WinPirate_offensive_tool_keyword = /c\:\\temp\\history\.html/ nocase ascii wide
                        $string35_WinPirate_offensive_tool_keyword = /c\:\\temp\\history\.txt/ nocase ascii wide
                        $string36_WinPirate_offensive_tool_keyword = /cp\s\\"\/media\/windows\/Windows\/System32\/cmd\.exe\\"\s\\"\/media\/windows\/Windows\/System32\// nocase ascii wide
                        $string37_WinPirate_offensive_tool_keyword = "d4962bf59508b527bd83622e1f05a95e3f26f2d7583052744e3d8dcdd08c4556" nocase ascii wide
                        $string38_WinPirate_offensive_tool_keyword = "de09af73cc55f3dfbf6bf40493075b3c93765aa0ad88e34b568eac727f6b0c03" nocase ascii wide
                        $string39_WinPirate_offensive_tool_keyword = /drops\sa\snetcat\?\?\sundetectable\sby\santivirus/ nocase ascii wide
                        $string40_WinPirate_offensive_tool_keyword = /icacls\sc\:\\windows\\system32\\sethc\.exe/ nocase ascii wide
                        $string41_WinPirate_offensive_tool_keyword = "l3m0n/WinPirate" nocase ascii wide
                        $string42_WinPirate_offensive_tool_keyword = /mv\s\\"\/media\/windows\/Windows\/System32\/sethc\.exe\\"\s\\"\/media\/windows\/Windows\/System32\// nocase ascii wide
                        $string43_WinPirate_offensive_tool_keyword = "REM getting browser history" nocase ascii wide
                        $string44_WinPirate_offensive_tool_keyword = "REM wipe the logs" nocase ascii wide
                        $string45_WinPirate_offensive_tool_keyword = /ren\ssethc\.exe\ssethcbad\.exe/ nocase ascii wide
                        $string46_WinPirate_offensive_tool_keyword = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
                        $string47_WinPirate_offensive_tool_keyword = /ren\ssethcold\.exe\ssethc\.exe/ nocase ascii wide
                        $string48_WinPirate_offensive_tool_keyword = /takeown\s\/f\sc\:\\windows\\system32\\sethc\.exe/ nocase ascii wide
                        $string49_WinPirate_offensive_tool_keyword = /takeown\s\/f\sc\:\\windows\\system32\\sethcold\.exe/ nocase ascii wide
                        $string50_WinPirate_offensive_tool_keyword = /Windows\/System32\/cmdlol\.exe/ nocase ascii wide

    condition:
        any of them
}