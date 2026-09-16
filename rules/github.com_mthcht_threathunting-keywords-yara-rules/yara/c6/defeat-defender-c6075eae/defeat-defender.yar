rule Defeat_Defender
{
    meta:
        description = "Detection patterns for the tool 'Defeat-Defender' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Defeat-Defender"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " ediH:edoMwodniWwohS-" nocase ascii wide
                        $string2 = /\sNSudo\.exe/ nocase ascii wide
                        $string3 = " T:U- odusN" nocase ascii wide
                        $string4 = " -U:T -ShowWindowMode:Hide reg add " nocase ascii wide
                        $string5 = /\.exe\s\-U\:T\sicacls\s/ nocase ascii wide
                        $string6 = /\.exe\s\-U\:T\stakeown\s\/f.{0,1000}\\smartscreen\.exe/ nocase ascii wide
                        $string7 = /\/\/\:sptth\\"\[\:\:\-1\]/ nocase ascii wide
                        $string8 = /\/Defeat\-Defender\-V1\.2\.0\.git/ nocase ascii wide
                        $string9 = /\/NSudo\.bat/ nocase ascii wide
                        $string10 = /\/NSudo\.exe/ nocase ascii wide
                        $string11 = /\/NSudoG\.exe/ nocase ascii wide
                        $string12 = /\:\s\sDefeat\-Defender\-V1\.2\.0/ nocase ascii wide
                        $string13 = /\\Defeat\-Defender\-V1\.2\.0\-main/ nocase ascii wide
                        $string14 = /\\disableav\.bat/ nocase ascii wide
                        $string15 = /\\NSudo\.bat/ nocase ascii wide
                        $string16 = /\\NSudo\.exe/ nocase ascii wide
                        $string17 = /\\NSudoC\.exe/ nocase ascii wide
                        $string18 = /\\NSudoG\.exe/ nocase ascii wide
                        $string19 = "19896a23d7b054625c2f6b1ee1551a0da68ad25cddbb24510a3b74578418e618" nocase ascii wide
                        $string20 = "38f4134e67348c6eb804f52463d9b3716ffa93ead0db4aa21ff9231bc91fc52a" nocase ascii wide
                        $string21 = "a93513b46fd03b0bec44784379a68f6564a84691392da67baefe36dddd85f3f9" nocase ascii wide
                        $string22 = "d0684a4f8a1dde0fefa5272d38fd96c21388f0398beff1a2847ff0c021611068" nocase ascii wide
                        $string23 = "d0f189f26ac306b46efc221359e27629eb76c54a4cf0cec4e3731ab306bee0af" nocase ascii wide
                        $string24 = /Defeat\-Defender\.bat/ nocase ascii wide
                        $string25 = /defeat\-defender\.py/ nocase ascii wide
                        $string26 = /Defeat\-Defender\-V1\.3\.ahk/ nocase ascii wide
                        $string27 = "dnefedniw  eteled cs" nocase ascii wide
                        $string28 = /echo\sbitsadmin\s\/transfer\sPackages\s\/download\s\/priority\sforeground\s\%a\%\s\\"\%USERPROFILE\%\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\Winupdate\.exe/ nocase ascii wide
                        $string29 = /echo\spowershell\s\-command\s\\"start\sWinupdate\.exe\\"\s\>\>.{0,1000}\.bat/ nocase ascii wide
                        $string30 = /echo\sUAC\.ShellExecute\s.{0,1000}cmd\.exe/ nocase ascii wide
                        $string31 = "Enter the Direct Link of malware : " nocase ascii wide
                        $string32 = /File\sGenerated\sSuccessfully\.Run\sDefeat\-Defender\.bat\son\starget\smachine/ nocase ascii wide
                        $string33 = "malwareurl = \"https:" nocase ascii wide
                        $string34 = /moc\.tnetnocresubuhtig\.war\/\/\:sptth/ nocase ascii wide
                        $string35 = "niam/noitcetorP-repmaT-ssapyB" nocase ascii wide
                        $string36 = "NSudo -U:T -ShowWindowMode:Hide" nocase ascii wide
                        $string37 = /Please\sDont\supload\ssample\sanywhere.{0,1000}Its\sbeen\sfifth\stime\si\sam\sagain\smaking\sthis\sscript\sfud/ nocase ascii wide
                        $string38 = "'Please Turn off your Windows Defender'" nocase ascii wide
                        $string39 = /powershell\.exe\s\-command\s\\"Add\-MpPreference\s\-ExclusionExtension\s\\"\.exe\\"/ nocase ascii wide
                        $string40 = /raw\.githubusercontent\.com\/swagkarna\/Bypass\-Tamper\-Protection/ nocase ascii wide
                        $string41 = "Set-MpPreference -PUAProtection disable" nocase ascii wide
                        $string42 = "-ShowWindowMode:Hide sc stop WinDefend" nocase ascii wide
                        $string43 = "swagkarna/Defeat-Defender-V" nocase ascii wide
                        $string44 = /takeown\s\/f\s\\"\%systemroot\%\\System32\\smartscreen\.exe\\"\s\/a/ nocase ascii wide
                        $string45 = /\'Windows\sDefender\shas\sblocked\ssome\sof\sour\sFeatures\.Please\sTurn\soff\sWindows\sDefender\sand\srun\sagain/ nocase ascii wide

    condition:
        any of them
}