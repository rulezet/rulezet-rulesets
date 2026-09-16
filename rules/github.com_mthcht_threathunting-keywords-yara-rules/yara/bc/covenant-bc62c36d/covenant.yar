rule covenant
{
    meta:
        description = "Detection patterns for the tool 'covenant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "covenant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --name covenant " nocase ascii wide
                        $string2 = " start covenant" nocase ascii wide
                        $string3 = " stop covenant" nocase ascii wide
                        $string4 = "/Brute/BruteStager" nocase ascii wide
                        $string5 = /\/BruteStager\.cs/ nocase ascii wide
                        $string6 = /\/Covenant.{0,1000}\.cs/ nocase ascii wide
                        $string7 = /\/Covenant\.git/ nocase ascii wide
                        $string8 = "/Covenant/" nocase ascii wide
                        $string9 = "/CovenantUsers/" nocase ascii wide
                        $string10 = /\/GruntHTTP\.exe/ nocase ascii wide
                        $string11 = /\/Models\/PowerShellLauncher\./ nocase ascii wide
                        $string12 = /\/Models\/Regsvr32Launcher\./ nocase ascii wide
                        $string13 = /\/Models\/ShellCodeLauncher\./ nocase ascii wide
                        $string14 = "/opt/Covenant/Covenant/"
                        $string15 = "/SharpDump" nocase ascii wide
                        $string16 = "/SharpSploit" nocase ascii wide
                        $string17 = /\/WhoAmI\.task/ nocase ascii wide
                        $string18 = /\\Elite\.csproj/ nocase ascii wide
                        $string19 = /\\Elite\.sln/ nocase ascii wide
                        $string20 = /Brute\/Brute\.cs/ nocase ascii wide
                        $string21 = /Brute\/Brute\.csproj/ nocase ascii wide
                        $string22 = /Brute\/Brute\.sln/ nocase ascii wide
                        $string23 = /BruteStager\.csproj/ nocase ascii wide
                        $string24 = /BruteStager\.sln/ nocase ascii wide
                        $string25 = /CapturedCredential\.cs/ nocase ascii wide
                        $string26 = /CapturedCredential\.exe/ nocase ascii wide
                        $string27 = /CapturedHashCredential\./ nocase ascii wide
                        $string28 = /CapturedPasswordCredential\./ nocase ascii wide
                        $string29 = /CapturedTicketCredential\./ nocase ascii wide
                        $string30 = "cobbr/Covenant" nocase ascii wide
                        $string31 = "cobbr/Elite" nocase ascii wide
                        $string32 = /Covenant\.API/ nocase ascii wide
                        $string33 = /Covenant\.csproj/ nocase ascii wide
                        $string34 = /Covenant\.exe/ nocase ascii wide
                        $string35 = /Covenant\.Models/ nocase ascii wide
                        $string36 = /Covenant\.sln/ nocase ascii wide
                        $string37 = "Covenant/Covenant" nocase ascii wide
                        $string38 = "Covenant/wwwroot" nocase ascii wide
                        $string39 = /CovenantAPI\./ nocase ascii wide
                        $string40 = /CovenantAPIExtensions\./ nocase ascii wide
                        $string41 = /CovenantBaseMenuItem\./ nocase ascii wide
                        $string42 = /CovenantService\.cs/ nocase ascii wide
                        $string43 = /CovenantUser\.cs/ nocase ascii wide
                        $string44 = /CovenantUserLogin\./ nocase ascii wide
                        $string45 = /CovenantUserLoginResult\./ nocase ascii wide
                        $string46 = /CovenantUserRegister\./ nocase ascii wide
                        $string47 = /docker\s.{0,1000}\scovenant/ nocase ascii wide
                        $string48 = /docker\s.{0,1000}\s\-\-name\selite\s/ nocase ascii wide
                        $string49 = /docker\s.{0,1000}\s\-t\selite\s/ nocase ascii wide
                        $string50 = "donut-loader -" nocase ascii wide
                        $string51 = /donut\-maker\.py\s\-/ nocase ascii wide
                        $string52 = "donut-shellcode" nocase ascii wide
                        $string53 = /GruntInjection\.exe/ nocase ascii wide
                        $string54 = /gruntstager\.cs/ nocase ascii wide
                        $string55 = /GruntStager\.exe/ nocase ascii wide
                        $string56 = /http.{0,1000}127\.0\.0\.1\:57230/ nocase ascii wide
                        $string57 = /http.{0,1000}localhost\:57230/ nocase ascii wide
                        $string58 = /https\:\/\/127\.0\.0\.1\:7443/ nocase ascii wide
                        $string59 = "https://localhost:7443/" nocase ascii wide
                        $string60 = /obfuscate\.py\sgrunt/ nocase ascii wide
                        $string61 = /powerkatz_x64\.dll/ nocase ascii wide
                        $string62 = /powerkatz_x86\.dll/ nocase ascii wide
                        $string63 = "SharpUp audit" nocase ascii wide
                        $string64 = /ShellCmd\scmd\.exe\s/ nocase ascii wide
                        $string65 = "ShellCmd copy " nocase ascii wide
                        $string66 = "ShellCmd net " nocase ascii wide
                        $string67 = "ShellCmd sc qc " nocase ascii wide
                        $string68 = "BypassUAC " nocase ascii wide

    condition:
        any of them
}