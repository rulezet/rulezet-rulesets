rule rule_Defeat_Defender_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Defeat-Defender' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Defeat-Defender"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Defeat_Defender_offensive_tool_keyword = " ediH:edoMwodniWwohS-" nocase ascii wide
                        $string2_Defeat_Defender_offensive_tool_keyword = /\sNSudo\.exe/ nocase ascii wide
                        $string3_Defeat_Defender_offensive_tool_keyword = " T:U- odusN" nocase ascii wide
                        $string4_Defeat_Defender_offensive_tool_keyword = " -U:T -ShowWindowMode:Hide reg add " nocase ascii wide
                        $string5_Defeat_Defender_offensive_tool_keyword = /\.exe\s\-U\:T\sicacls\s/ nocase ascii wide
                        $string6_Defeat_Defender_offensive_tool_keyword = /\.exe\s\-U\:T\stakeown\s\/f.{0,1000}\\smartscreen\.exe/ nocase ascii wide
                        $string7_Defeat_Defender_offensive_tool_keyword = /\/\/\:sptth\\"\[\:\:\-1\]/ nocase ascii wide
                        $string8_Defeat_Defender_offensive_tool_keyword = /\/Defeat\-Defender\-V1\.2\.0\.git/ nocase ascii wide
                        $string9_Defeat_Defender_offensive_tool_keyword = /\/NSudo\.bat/ nocase ascii wide
                        $string10_Defeat_Defender_offensive_tool_keyword = /\/NSudo\.exe/ nocase ascii wide
                        $string11_Defeat_Defender_offensive_tool_keyword = /\/NSudoG\.exe/ nocase ascii wide
                        $string12_Defeat_Defender_offensive_tool_keyword = /\:\s\sDefeat\-Defender\-V1\.2\.0/ nocase ascii wide
                        $string13_Defeat_Defender_offensive_tool_keyword = /\\Defeat\-Defender\-V1\.2\.0\-main/ nocase ascii wide
                        $string14_Defeat_Defender_offensive_tool_keyword = /\\disableav\.bat/ nocase ascii wide
                        $string15_Defeat_Defender_offensive_tool_keyword = /\\NSudo\.bat/ nocase ascii wide
                        $string16_Defeat_Defender_offensive_tool_keyword = /\\NSudo\.exe/ nocase ascii wide
                        $string17_Defeat_Defender_offensive_tool_keyword = /\\NSudoC\.exe/ nocase ascii wide
                        $string18_Defeat_Defender_offensive_tool_keyword = /\\NSudoG\.exe/ nocase ascii wide
                        $string19_Defeat_Defender_offensive_tool_keyword = "19896a23d7b054625c2f6b1ee1551a0da68ad25cddbb24510a3b74578418e618" nocase ascii wide
                        $string20_Defeat_Defender_offensive_tool_keyword = "38f4134e67348c6eb804f52463d9b3716ffa93ead0db4aa21ff9231bc91fc52a" nocase ascii wide
                        $string21_Defeat_Defender_offensive_tool_keyword = "a93513b46fd03b0bec44784379a68f6564a84691392da67baefe36dddd85f3f9" nocase ascii wide
                        $string22_Defeat_Defender_offensive_tool_keyword = "d0684a4f8a1dde0fefa5272d38fd96c21388f0398beff1a2847ff0c021611068" nocase ascii wide
                        $string23_Defeat_Defender_offensive_tool_keyword = "d0f189f26ac306b46efc221359e27629eb76c54a4cf0cec4e3731ab306bee0af" nocase ascii wide
                        $string24_Defeat_Defender_offensive_tool_keyword = /Defeat\-Defender\.bat/ nocase ascii wide
                        $string25_Defeat_Defender_offensive_tool_keyword = /defeat\-defender\.py/ nocase ascii wide
                        $string26_Defeat_Defender_offensive_tool_keyword = /Defeat\-Defender\-V1\.3\.ahk/ nocase ascii wide
                        $string27_Defeat_Defender_offensive_tool_keyword = "dnefedniw  eteled cs" nocase ascii wide
                        $string28_Defeat_Defender_offensive_tool_keyword = /echo\sbitsadmin\s\/transfer\sPackages\s\/download\s\/priority\sforeground\s\%a\%\s\\"\%USERPROFILE\%\\AppData\\Roaming\\Microsoft\\Windows\\Start\sMenu\\Programs\\Startup\\Winupdate\.exe/ nocase ascii wide
                        $string29_Defeat_Defender_offensive_tool_keyword = /echo\spowershell\s\-command\s\\"start\sWinupdate\.exe\\"\s\>\>.{0,1000}\.bat/ nocase ascii wide
                        $string30_Defeat_Defender_offensive_tool_keyword = /echo\sUAC\.ShellExecute\s.{0,1000}cmd\.exe/ nocase ascii wide
                        $string31_Defeat_Defender_offensive_tool_keyword = "Enter the Direct Link of malware : " nocase ascii wide
                        $string32_Defeat_Defender_offensive_tool_keyword = /File\sGenerated\sSuccessfully\.Run\sDefeat\-Defender\.bat\son\starget\smachine/ nocase ascii wide
                        $string33_Defeat_Defender_offensive_tool_keyword = "malwareurl = \"https:" nocase ascii wide
                        $string34_Defeat_Defender_offensive_tool_keyword = /moc\.tnetnocresubuhtig\.war\/\/\:sptth/ nocase ascii wide
                        $string35_Defeat_Defender_offensive_tool_keyword = "niam/noitcetorP-repmaT-ssapyB" nocase ascii wide
                        $string36_Defeat_Defender_offensive_tool_keyword = "NSudo -U:T -ShowWindowMode:Hide" nocase ascii wide
                        $string37_Defeat_Defender_offensive_tool_keyword = /Please\sDont\supload\ssample\sanywhere.{0,1000}Its\sbeen\sfifth\stime\si\sam\sagain\smaking\sthis\sscript\sfud/ nocase ascii wide
                        $string38_Defeat_Defender_offensive_tool_keyword = "'Please Turn off your Windows Defender'" nocase ascii wide
                        $string39_Defeat_Defender_offensive_tool_keyword = /powershell\.exe\s\-command\s\\"Add\-MpPreference\s\-ExclusionExtension\s\\"\.exe\\"/ nocase ascii wide
                        $string40_Defeat_Defender_offensive_tool_keyword = /raw\.githubusercontent\.com\/swagkarna\/Bypass\-Tamper\-Protection/ nocase ascii wide
                        $string41_Defeat_Defender_offensive_tool_keyword = "Set-MpPreference -PUAProtection disable" nocase ascii wide
                        $string42_Defeat_Defender_offensive_tool_keyword = "-ShowWindowMode:Hide sc stop WinDefend" nocase ascii wide
                        $string43_Defeat_Defender_offensive_tool_keyword = "swagkarna/Defeat-Defender-V" nocase ascii wide
                        $string44_Defeat_Defender_offensive_tool_keyword = /takeown\s\/f\s\\"\%systemroot\%\\System32\\smartscreen\.exe\\"\s\/a/ nocase ascii wide
                        $string45_Defeat_Defender_offensive_tool_keyword = /\'Windows\sDefender\shas\sblocked\ssome\sof\sour\sFeatures\.Please\sTurn\soff\sWindows\sDefender\sand\srun\sagain/ nocase ascii wide

    condition:
        any of them
}