rule rule_Accomplice_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Accomplice' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Accomplice"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Accomplice_offensive_tool_keyword = /\sCOMHijackToolkit\.ps1/ nocase ascii wide
                        $string2_Accomplice_offensive_tool_keyword = /\sHijackDLL\-Threads\.dll/ nocase ascii wide
                        $string3_Accomplice_offensive_tool_keyword = /\/Accomplice\.git/ nocase ascii wide
                        $string4_Accomplice_offensive_tool_keyword = /\/COMHijackToolkit\.ps1/ nocase ascii wide
                        $string5_Accomplice_offensive_tool_keyword = /\/COMInjectTarget\.dll/ nocase ascii wide
                        $string6_Accomplice_offensive_tool_keyword = /\/HijackDLL\-CreateRemoteThread\.cpp/ nocase ascii wide
                        $string7_Accomplice_offensive_tool_keyword = /\/HijackDll\-Process\.cpp/ nocase ascii wide
                        $string8_Accomplice_offensive_tool_keyword = /\/HijackDLL\-Threads\./ nocase ascii wide
                        $string9_Accomplice_offensive_tool_keyword = /\\COMHijackToolkit\.ps1/ nocase ascii wide
                        $string10_Accomplice_offensive_tool_keyword = /\\COMHijackToolkit\\/ nocase ascii wide
                        $string11_Accomplice_offensive_tool_keyword = /\\COMInject\.exe/ nocase ascii wide
                        $string12_Accomplice_offensive_tool_keyword = /\\COMInject\.sln/ nocase ascii wide
                        $string13_Accomplice_offensive_tool_keyword = /\\COMInjectTarget\.cpp/ nocase ascii wide
                        $string14_Accomplice_offensive_tool_keyword = /\\COMInjectTarget\.dll/ nocase ascii wide
                        $string15_Accomplice_offensive_tool_keyword = /\\COMInjectTarget\\/ nocase ascii wide
                        $string16_Accomplice_offensive_tool_keyword = /\\HijackDLL\-CreateRemoteThread\./ nocase ascii wide
                        $string17_Accomplice_offensive_tool_keyword = /\\HijackDLL\-CreateRemoteThread\\/ nocase ascii wide
                        $string18_Accomplice_offensive_tool_keyword = /\\HijackDll\-Process\./ nocase ascii wide
                        $string19_Accomplice_offensive_tool_keyword = /\\HijackDLL\-Threads\./ nocase ascii wide
                        $string20_Accomplice_offensive_tool_keyword = "06e8a15602cc6001db8ac6d14c4cf938a92aab83a446bcd5c2c4334ad4b44e6e" nocase ascii wide
                        $string21_Accomplice_offensive_tool_keyword = "1FDCAD33-E5D1-4D5F-ACD5-FA6F8661DFE5" nocase ascii wide
                        $string22_Accomplice_offensive_tool_keyword = "25aac4494a46799c4755d9bda39314d628134ee58dd6f724ee905373c3600343" nocase ascii wide
                        $string23_Accomplice_offensive_tool_keyword = "2a3035797a103e527b1645cb90fccf165b76deea5b1526d80f66e32f5082e0d0" nocase ascii wide
                        $string24_Accomplice_offensive_tool_keyword = "56cfc4ef19c92043b59bb88846ffd69725df417bd4c7adf14aa11e29a9428acc" nocase ascii wide
                        $string25_Accomplice_offensive_tool_keyword = "ADCEEFBA-CE43-4239-8AE8-7D8D43E66BB1" nocase ascii wide
                        $string26_Accomplice_offensive_tool_keyword = "BB8A69C4-18B0-4FF2-989C-F70778FFBCE6" nocase ascii wide
                        $string27_Accomplice_offensive_tool_keyword = "C37637FC-3792-4354-8F5B-7E319E4E5A6D" nocase ascii wide
                        $string28_Accomplice_offensive_tool_keyword = "c786890a660e4bca317ce667bc660504f8167a5d5965867d748ed02d0caa5046" nocase ascii wide
                        $string29_Accomplice_offensive_tool_keyword = /COMInjectDotNet\.exe/ nocase ascii wide
                        $string30_Accomplice_offensive_tool_keyword = "d80804bbcdbdd1933da9d9b7c0457ae73b85026e71970d1ab80af063b8fbac2e" nocase ascii wide
                        $string31_Accomplice_offensive_tool_keyword = "Extract-HijackableKeysFromProcmonCSV" nocase ascii wide
                        $string32_Accomplice_offensive_tool_keyword = "F90C57DF-CDE4-4CDE-A2B9-9124C307D53A" nocase ascii wide
                        $string33_Accomplice_offensive_tool_keyword = "Get-CLSIDRegistryKeys -RegHive " nocase ascii wide
                        $string34_Accomplice_offensive_tool_keyword = "Hijack-MultipleKeys -dll " nocase ascii wide
                        $string35_Accomplice_offensive_tool_keyword = "nccgroup/Accomplice" nocase ascii wide

    condition:
        any of them
}