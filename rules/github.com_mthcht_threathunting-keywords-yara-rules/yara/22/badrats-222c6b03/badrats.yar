rule badrats
{
    meta:
        description = "Detection patterns for the tool 'badrats' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badrats"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbadrat\.ps1/ nocase ascii wide
                        $string2 = /\sbadrat_cs\.exe/ nocase ascii wide
                        $string3 = /\sbadrat_server\.py/ nocase ascii wide
                        $string4 = /\s\-o\:badrat\.xll\s/ nocase ascii wide
                        $string5 = /\/badrat\.ps1/ nocase ascii wide
                        $string6 = /\/badrat_cs\.exe/ nocase ascii wide
                        $string7 = /\/badrat_server\.py/ nocase ascii wide
                        $string8 = /\/badrats\.git/ nocase ascii wide
                        $string9 = /\/dbsclrxcvg\/b\.js/ nocase ascii wide
                        $string10 = "/rats/badrat_cs/" nocase ascii wide
                        $string11 = /\[\!\]\sFeature\sis\sunsupported\sfor\sPS1\srats/ nocase ascii wide
                        $string12 = /\[\!\]\sNim\sand\sC\#\sare\sthe\sonly\slanguage\scapable\sof\sexecuting\sBOFS/ nocase ascii wide
                        $string13 = /\\badrat\.ps1/ nocase ascii wide
                        $string14 = /\\badrat_cs\.exe/ nocase ascii wide
                        $string15 = /\\badrat_server\.py/ nocase ascii wide
                        $string16 = /\\rats\\badrat_cs\\/ nocase ascii wide
                        $string17 = /\\rats\\js_downloader\.vba/ nocase ascii wide
                        $string18 = /\\shellcode_createproc\.xml/ nocase ascii wide
                        $string19 = /\]\sCleared\sall\srat\scommand\squeues\!/ nocase ascii wide
                        $string20 = "79520C3A-4931-46EB-92D7-334DA7FC9013" nocase ascii wide
                        $string21 = /badrat\.smb\.hta/ nocase ascii wide
                        $string22 = /badrat\.smb\.js/ nocase ascii wide
                        $string23 = /badrat_cs\.csproj/ nocase ascii wide
                        $string24 = /badrat_cs\.exe\s/ nocase ascii wide
                        $string25 = /badrat_cs\.exe\.config/ nocase ascii wide
                        $string26 = /badrat_server\.py\s/ nocase ascii wide
                        $string27 = /badrats\-c2\-initial\-access\-payloads\.html/ nocase ascii wide
                        $string28 = /badrats\-master\.zip/ nocase ascii wide
                        $string29 = /Invoke\-Bloodhound\.ps1/ nocase ascii wide
                        $string30 = "Invoke-ReverseSocksProxy" nocase ascii wide
                        $string31 = /Invoke\-SocksProxy\.ps1/ nocase ascii wide
                        $string32 = "KevinJClark/badrats" nocase ascii wide
                        $string33 = /rat\scommunications\sare\sNOT\sSECURE\.\sDo\snot\ssend\ssensitive\sinfo\sthrough\sthe\sC2\schannel\sunless\susing\sSSL/ nocase ascii wide
                        $string34 = /send_invoke_shellcode\(.{0,1000}ratID/ nocase ascii wide
                        $string35 = /send_ratcode\(ratID\=/ nocase ascii wide
                        $string36 = /send_shellcode_msbuild_xml\(.{0,1000}ratID/ nocase ascii wide
                        $string37 = /sends\sthe\sjscript\sfile\sto\sthe\srat\s\(JS\sand\sHTA\sonly\)\sto\sbe\sevaulated\sin\sline\.\sUseful\sfor\sGadget2JS\spayloads/ nocase ascii wide
                        $string38 = "set-shellcode-process default" nocase ascii wide
                        $string39 = /SharpDump\.exe/ nocase ascii wide
                        $string40 = /shellcode_injectproc\.xml/ nocase ascii wide
                        $string41 = "unlink -- tells the current rat to disconnect from a child rat given a local file or UNC path" nocase ascii wide
                        $string42 = /xor_crypt_and_encode\(/ nocase ascii wide

    condition:
        any of them
}