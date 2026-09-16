rule rule_covenant_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'covenant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "covenant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_covenant_offensive_tool_keyword = " --name covenant " nocase ascii wide
                        $string2_covenant_offensive_tool_keyword = " start covenant" nocase ascii wide
                        $string3_covenant_offensive_tool_keyword = " stop covenant" nocase ascii wide
                        $string4_covenant_offensive_tool_keyword = "/Brute/BruteStager" nocase ascii wide
                        $string5_covenant_offensive_tool_keyword = /\/BruteStager\.cs/ nocase ascii wide
                        $string6_covenant_offensive_tool_keyword = /\/Covenant.{0,1000}\.cs/ nocase ascii wide
                        $string7_covenant_offensive_tool_keyword = /\/Covenant\.git/ nocase ascii wide
                        $string8_covenant_offensive_tool_keyword = "/Covenant/" nocase ascii wide
                        $string9_covenant_offensive_tool_keyword = "/CovenantUsers/" nocase ascii wide
                        $string10_covenant_offensive_tool_keyword = /\/GruntHTTP\.exe/ nocase ascii wide
                        $string11_covenant_offensive_tool_keyword = /\/Models\/PowerShellLauncher\./ nocase ascii wide
                        $string12_covenant_offensive_tool_keyword = /\/Models\/Regsvr32Launcher\./ nocase ascii wide
                        $string13_covenant_offensive_tool_keyword = /\/Models\/ShellCodeLauncher\./ nocase ascii wide
                        $string14_covenant_offensive_tool_keyword = "/opt/Covenant/Covenant/"
                        $string15_covenant_offensive_tool_keyword = "/SharpDump" nocase ascii wide
                        $string16_covenant_offensive_tool_keyword = "/SharpSploit" nocase ascii wide
                        $string17_covenant_offensive_tool_keyword = /\/WhoAmI\.task/ nocase ascii wide
                        $string18_covenant_offensive_tool_keyword = /\\Elite\.csproj/ nocase ascii wide
                        $string19_covenant_offensive_tool_keyword = /\\Elite\.sln/ nocase ascii wide
                        $string20_covenant_offensive_tool_keyword = /Brute\/Brute\.cs/ nocase ascii wide
                        $string21_covenant_offensive_tool_keyword = /Brute\/Brute\.csproj/ nocase ascii wide
                        $string22_covenant_offensive_tool_keyword = /Brute\/Brute\.sln/ nocase ascii wide
                        $string23_covenant_offensive_tool_keyword = /BruteStager\.csproj/ nocase ascii wide
                        $string24_covenant_offensive_tool_keyword = /BruteStager\.sln/ nocase ascii wide
                        $string25_covenant_offensive_tool_keyword = /CapturedCredential\.cs/ nocase ascii wide
                        $string26_covenant_offensive_tool_keyword = /CapturedCredential\.exe/ nocase ascii wide
                        $string27_covenant_offensive_tool_keyword = /CapturedHashCredential\./ nocase ascii wide
                        $string28_covenant_offensive_tool_keyword = /CapturedPasswordCredential\./ nocase ascii wide
                        $string29_covenant_offensive_tool_keyword = /CapturedTicketCredential\./ nocase ascii wide
                        $string30_covenant_offensive_tool_keyword = "cobbr/Covenant" nocase ascii wide
                        $string31_covenant_offensive_tool_keyword = "cobbr/Elite" nocase ascii wide
                        $string32_covenant_offensive_tool_keyword = /Covenant\.API/ nocase ascii wide
                        $string33_covenant_offensive_tool_keyword = /Covenant\.csproj/ nocase ascii wide
                        $string34_covenant_offensive_tool_keyword = /Covenant\.exe/ nocase ascii wide
                        $string35_covenant_offensive_tool_keyword = /Covenant\.Models/ nocase ascii wide
                        $string36_covenant_offensive_tool_keyword = /Covenant\.sln/ nocase ascii wide
                        $string37_covenant_offensive_tool_keyword = "Covenant/Covenant" nocase ascii wide
                        $string38_covenant_offensive_tool_keyword = "Covenant/wwwroot" nocase ascii wide
                        $string39_covenant_offensive_tool_keyword = /CovenantAPI\./ nocase ascii wide
                        $string40_covenant_offensive_tool_keyword = /CovenantAPIExtensions\./ nocase ascii wide
                        $string41_covenant_offensive_tool_keyword = /CovenantBaseMenuItem\./ nocase ascii wide
                        $string42_covenant_offensive_tool_keyword = /CovenantService\.cs/ nocase ascii wide
                        $string43_covenant_offensive_tool_keyword = /CovenantUser\.cs/ nocase ascii wide
                        $string44_covenant_offensive_tool_keyword = /CovenantUserLogin\./ nocase ascii wide
                        $string45_covenant_offensive_tool_keyword = /CovenantUserLoginResult\./ nocase ascii wide
                        $string46_covenant_offensive_tool_keyword = /CovenantUserRegister\./ nocase ascii wide
                        $string47_covenant_offensive_tool_keyword = /docker\s.{0,1000}\scovenant/ nocase ascii wide
                        $string48_covenant_offensive_tool_keyword = /docker\s.{0,1000}\s\-\-name\selite\s/ nocase ascii wide
                        $string49_covenant_offensive_tool_keyword = /docker\s.{0,1000}\s\-t\selite\s/ nocase ascii wide
                        $string50_covenant_offensive_tool_keyword = "donut-loader -" nocase ascii wide
                        $string51_covenant_offensive_tool_keyword = /donut\-maker\.py\s\-/ nocase ascii wide
                        $string52_covenant_offensive_tool_keyword = "donut-shellcode" nocase ascii wide
                        $string53_covenant_offensive_tool_keyword = /GruntInjection\.exe/ nocase ascii wide
                        $string54_covenant_offensive_tool_keyword = /gruntstager\.cs/ nocase ascii wide
                        $string55_covenant_offensive_tool_keyword = /GruntStager\.exe/ nocase ascii wide
                        $string56_covenant_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:57230/ nocase ascii wide
                        $string57_covenant_offensive_tool_keyword = /http.{0,1000}localhost\:57230/ nocase ascii wide
                        $string58_covenant_offensive_tool_keyword = /https\:\/\/127\.0\.0\.1\:7443/ nocase ascii wide
                        $string59_covenant_offensive_tool_keyword = "https://localhost:7443/" nocase ascii wide
                        $string60_covenant_offensive_tool_keyword = /obfuscate\.py\sgrunt/ nocase ascii wide
                        $string61_covenant_offensive_tool_keyword = /powerkatz_x64\.dll/ nocase ascii wide
                        $string62_covenant_offensive_tool_keyword = /powerkatz_x86\.dll/ nocase ascii wide
                        $string63_covenant_offensive_tool_keyword = "SharpUp audit" nocase ascii wide
                        $string64_covenant_offensive_tool_keyword = /ShellCmd\scmd\.exe\s/ nocase ascii wide
                        $string65_covenant_offensive_tool_keyword = "ShellCmd copy " nocase ascii wide
                        $string66_covenant_offensive_tool_keyword = "ShellCmd net " nocase ascii wide
                        $string67_covenant_offensive_tool_keyword = "ShellCmd sc qc " nocase ascii wide
                        $string68_covenant_offensive_tool_keyword = "BypassUAC " nocase ascii wide

    condition:
        any of them
}