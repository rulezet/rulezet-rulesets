rule Payload_Download_Cradles
{
    meta:
        description = "Detection patterns for the tool 'Payload-Download-Cradles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Payload-Download-Cradles"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " /c PoWErSheLl -nopROfi -EXe byPAsS -wiNDOwsTy HIDdEN -cOMMA " nocase ascii wide
                        $string2 = /\sCreateObject\(\\"W\\"\+\\"S\\"\+\\"cr\\"\+\\"ip\\"\+\\"t\.\\"\+\\"S\\"\+\\"h\\"\+\\"e\\"\+\\"l\\"\+\\"l\\"\)/ nocase ascii wide
                        $string3 = " danielbohannon/Invoke-CradleCrafter" nocase ascii wide
                        $string4 = /\sDownload_Cradles\.hta/ nocase ascii wide
                        $string5 = /\sDownload_Cradles\.ps1/ nocase ascii wide
                        $string6 = " -eXecut byPaSS -Noprof -w H -Co " nocase ascii wide
                        $string7 = /\s\-eXecUT\sbyPAss\s\-WINDo\s1\s\-nOpR\s\-coMm\s\\"\\"\&\s\(\(vARiaBlE\s\'.{0,1000}mdr.{0,1000}\'\)\.Name\[3\,11\,2\]\-JoiN\'\'\)/ nocase ascii wide
                        $string8 = " -eXecUT byPAss -WINDo 1 -nOpR -coMm " nocase ascii wide
                        $string9 = /\s\-NoP\s\-w\sHidDen\s\-c\s\$a\=neW\-ObJeCt\snET\.wEbClieNt/ nocase ascii wide
                        $string10 = " -nopROfi -EXe byPAsS -wiNDOwsTy HIDdEN -cOMMA " nocase ascii wide
                        $string11 = " -NopROFi -wIN hidd -EXEcutiOnPoLiC BYpAsS  -COm    " nocase ascii wide
                        $string12 = " -NoPRofi -WiNdoWSTYL hidd -EXecUTiOnPO BYpASS -cO " nocase ascii wide
                        $string13 = " -wINdOwstYL Hi -nop -eXecU BYpAss -COm  " nocase ascii wide
                        $string14 = /\$c\.Proxy\.Credentials\=\[Net\.CredentialCache\]\:\:DefaultCredentials\;\`i\`e\`x\s\$c\.downloadstring/ nocase ascii wide
                        $string15 = /\.\\\\"do\`wnLO\`ADS\`TRinG\\/ nocase ascii wide
                        $string16 = /\/Download\:Cradle\.js/ nocase ascii wide
                        $string17 = /\/Download_Cradles\.hta/ nocase ascii wide
                        $string18 = /\/Download_Cradles\.ps1/ nocase ascii wide
                        $string19 = /\/Download\-Cradles\.cmd/ nocase ascii wide
                        $string20 = /\/Payload\-Download\-Cradles\.git/ nocase ascii wide
                        $string21 = /\[System\.Windows\.Forms\.MessageBox\]\:\:Show\(\\"Congratulations\,\sit\slooks\slike\,\syour\sdownload\scradle\sis\sworking/ nocase ascii wide
                        $string22 = /\\Download\:Cradle\.js/ nocase ascii wide
                        $string23 = /\\Download_Cradles\.hta/ nocase ascii wide
                        $string24 = /\\Download_Cradles\.ps1/ nocase ascii wide
                        $string25 = /\\Download\-Cradles\.cmd/ nocase ascii wide
                        $string26 = "1ecb2406b796017446aa92b071d1f26f7fbf2a1a9c61f6b393437500518ec193" nocase ascii wide
                        $string27 = "61f31088bc43825c500d7d6f22dd7d259b56dd181c9a59650975bd5e9e91cb25" nocase ascii wide
                        $string28 = "a2be75dd7462fbb4753ae380a987351c51d6cd41ba5cc41f08242feeec1df06f" nocase ascii wide
                        $string29 = "b7b10a29015b41041519488dc632cd5b0b39358f56d388277d99304917be4a9d" nocase ascii wide
                        $string30 = /CreateObject\(\\"\\"W\\"\\"\+\\"\\"S\\"\\"\+\\"\\"cr\\"\\"\+\\"\\"ip\\"\\"\+\\"\\"t\.\\"\\"\+\\"\\"S\\"\\"\+\\"\\"h\\"\\"\+\\"\\"e\\"\\"\+\\"\\"l\\"\\"\+\\"\\"l\\"\\"/ nocase ascii wide
                        $string31 = /Download\:Cradle\.js/ nocase ascii wide
                        $string32 = /Download_Cradles\./ nocase ascii wide
                        $string33 = /Download\-Cradles\.cmd/ nocase ascii wide
                        $string34 = /hidd\s\-EXecUTiOnPO\sBYpASS\s\-cO\s\s\\"i\`EX\s\(\s\s\s\sneW\-o\`BJE\`cT\sN\`ET\.\`weBcl\`IeNT\s\s\s\s\)/ nocase ascii wide
                        $string35 = /https\:\/\/cutt\.ly\/syFzILH/ nocase ascii wide
                        $string36 = /https\:\/\/pastebin\.com\/raw\/88SGrHVh/ nocase ascii wide
                        $string37 = "Invoke-CradleCrafter " nocase ascii wide
                        $string38 = "Payload-Download-Cradles" nocase ascii wide
                        $string39 = /\'ps\'\+\'\:\'\+\'\/\'\+\'\/\'\+\'cutt\.ly\/syFzIL/ nocase ascii wide
                        $string40 = "VirtualAlllocEx/Payload-Download-Cradles" nocase ascii wide

    condition:
        any of them
}