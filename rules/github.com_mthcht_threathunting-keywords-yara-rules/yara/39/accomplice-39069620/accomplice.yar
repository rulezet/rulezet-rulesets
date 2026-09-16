rule Accomplice
{
    meta:
        description = "Detection patterns for the tool 'Accomplice' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Accomplice"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCOMHijackToolkit\.ps1/ nocase ascii wide
                        $string2 = /\sHijackDLL\-Threads\.dll/ nocase ascii wide
                        $string3 = /\/Accomplice\.git/ nocase ascii wide
                        $string4 = /\/COMHijackToolkit\.ps1/ nocase ascii wide
                        $string5 = /\/COMInjectTarget\.dll/ nocase ascii wide
                        $string6 = /\/HijackDLL\-CreateRemoteThread\.cpp/ nocase ascii wide
                        $string7 = /\/HijackDll\-Process\.cpp/ nocase ascii wide
                        $string8 = /\/HijackDLL\-Threads\./ nocase ascii wide
                        $string9 = /\\COMHijackToolkit\.ps1/ nocase ascii wide
                        $string10 = /\\COMHijackToolkit\\/ nocase ascii wide
                        $string11 = /\\COMInject\.exe/ nocase ascii wide
                        $string12 = /\\COMInject\.sln/ nocase ascii wide
                        $string13 = /\\COMInjectTarget\.cpp/ nocase ascii wide
                        $string14 = /\\COMInjectTarget\.dll/ nocase ascii wide
                        $string15 = /\\COMInjectTarget\\/ nocase ascii wide
                        $string16 = /\\HijackDLL\-CreateRemoteThread\./ nocase ascii wide
                        $string17 = /\\HijackDLL\-CreateRemoteThread\\/ nocase ascii wide
                        $string18 = /\\HijackDll\-Process\./ nocase ascii wide
                        $string19 = /\\HijackDLL\-Threads\./ nocase ascii wide
                        $string20 = "06e8a15602cc6001db8ac6d14c4cf938a92aab83a446bcd5c2c4334ad4b44e6e" nocase ascii wide
                        $string21 = "1FDCAD33-E5D1-4D5F-ACD5-FA6F8661DFE5" nocase ascii wide
                        $string22 = "25aac4494a46799c4755d9bda39314d628134ee58dd6f724ee905373c3600343" nocase ascii wide
                        $string23 = "2a3035797a103e527b1645cb90fccf165b76deea5b1526d80f66e32f5082e0d0" nocase ascii wide
                        $string24 = "56cfc4ef19c92043b59bb88846ffd69725df417bd4c7adf14aa11e29a9428acc" nocase ascii wide
                        $string25 = "ADCEEFBA-CE43-4239-8AE8-7D8D43E66BB1" nocase ascii wide
                        $string26 = "BB8A69C4-18B0-4FF2-989C-F70778FFBCE6" nocase ascii wide
                        $string27 = "C37637FC-3792-4354-8F5B-7E319E4E5A6D" nocase ascii wide
                        $string28 = "c786890a660e4bca317ce667bc660504f8167a5d5965867d748ed02d0caa5046" nocase ascii wide
                        $string29 = /COMInjectDotNet\.exe/ nocase ascii wide
                        $string30 = "d80804bbcdbdd1933da9d9b7c0457ae73b85026e71970d1ab80af063b8fbac2e" nocase ascii wide
                        $string31 = "Extract-HijackableKeysFromProcmonCSV" nocase ascii wide
                        $string32 = "F90C57DF-CDE4-4CDE-A2B9-9124C307D53A" nocase ascii wide
                        $string33 = "Get-CLSIDRegistryKeys -RegHive " nocase ascii wide
                        $string34 = "Hijack-MultipleKeys -dll " nocase ascii wide
                        $string35 = "nccgroup/Accomplice" nocase ascii wide

    condition:
        any of them
}