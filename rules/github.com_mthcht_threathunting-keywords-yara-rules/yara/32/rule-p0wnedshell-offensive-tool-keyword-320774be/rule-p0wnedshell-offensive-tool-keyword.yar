rule rule_p0wnedShell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'p0wnedShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "p0wnedShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_p0wnedShell_offensive_tool_keyword = /\sPS1ToBase64\.ps1/ nocase ascii wide
                        $string2_p0wnedShell_offensive_tool_keyword = /\/Inveigh\-Log\.txt/
                        $string3_p0wnedShell_offensive_tool_keyword = /\/PS1ToBase64\.ps1/ nocase ascii wide
                        $string4_p0wnedShell_offensive_tool_keyword = /\\\\\.\\pipe\\EasySystem/ nocase ascii wide
                        $string5_p0wnedShell_offensive_tool_keyword = /\\\\\\\\\.\\\\pipe\\\\EasySystem/ nocase ascii wide
                        $string6_p0wnedShell_offensive_tool_keyword = /\\BloodHound\.bin/ nocase ascii wide
                        $string7_p0wnedShell_offensive_tool_keyword = /\\Inveigh\-Log\.txt/ nocase ascii wide
                        $string8_p0wnedShell_offensive_tool_keyword = /\\p0wnedAmsiBypass\./ nocase ascii wide
                        $string9_p0wnedShell_offensive_tool_keyword = /\\p0wnedExecute\./ nocase ascii wide
                        $string10_p0wnedShell_offensive_tool_keyword = /\\p0wnedInveigh\./ nocase ascii wide
                        $string11_p0wnedShell_offensive_tool_keyword = /\\p0wnedPotato\./ nocase ascii wide
                        $string12_p0wnedShell_offensive_tool_keyword = /\\p0wnedSystem\./ nocase ascii wide
                        $string13_p0wnedShell_offensive_tool_keyword = /\\PS1ToBase64\.ps1/ nocase ascii wide
                        $string14_p0wnedShell_offensive_tool_keyword = "2E9B1462-F47C-48CA-9D85-004493892381" nocase ascii wide
                        $string15_p0wnedShell_offensive_tool_keyword = "3c2d248fa4df74a0a05d7bdfba9a4796938c20fed174912c2a35c7c97e22f7e3" nocase ascii wide
                        $string16_p0wnedShell_offensive_tool_keyword = "43a7a1b32cc0536407af440786bb716c90f309647e1da3eda3d21fbd08b2338f" nocase ascii wide
                        $string17_p0wnedShell_offensive_tool_keyword = "5cbfbb972be8b3611722c133a87a7771f871f5cd6f10f1d2cf3043a2c3c11cd3" nocase ascii wide
                        $string18_p0wnedShell_offensive_tool_keyword = "71257aa853990279a1801d95495b3fd05c5b9b15d4983289d41f947003c8bce6" nocase ascii wide
                        $string19_p0wnedShell_offensive_tool_keyword = "716f0192964bd6c83ec16d8c12ff0e6a3e93d34dcb50c340412e5b63329c214a" nocase ascii wide
                        $string20_p0wnedShell_offensive_tool_keyword = "8dc950cda4cee750819dbb8c1f0b3dd2ba3e8a51679854517be8f619c8e2e736" nocase ascii wide
                        $string21_p0wnedShell_offensive_tool_keyword = "91c48bd880c65a28a50697f38aa6b246db7cb0e629a440c35a9a802d2e9da48c" nocase ascii wide
                        $string22_p0wnedShell_offensive_tool_keyword = "97de480818edd99fc1a118eb9e832db08910eb44cc3b53ebfd534b6c3afe4ee4" nocase ascii wide
                        $string23_p0wnedShell_offensive_tool_keyword = "acffa7660aefbd032bf1125b81cbd9927ff4edb5e0a8d5b05200cdde90a42714" nocase ascii wide
                        $string24_p0wnedShell_offensive_tool_keyword = "By Cn33liz and Skons 2018" nocase ascii wide
                        $string25_p0wnedShell_offensive_tool_keyword = "d65a7eed824f91e0ff00f273650903c1e14335dab57480e6e09a83675c4b407a" nocase ascii wide
                        $string26_p0wnedShell_offensive_tool_keyword = "e290d98bd79a5f643d384efdf56a7c6c383c12efd3c810bf4513dda266cd7935" nocase ascii wide
                        $string27_p0wnedShell_offensive_tool_keyword = /Get\-Content\s\.\/EncodedPayload\.bat/
                        $string28_p0wnedShell_offensive_tool_keyword = /Get\-Content\s\.\/Roast\.hash/
                        $string29_p0wnedShell_offensive_tool_keyword = /Get\-GPPPassword\s\|\smore/ nocase ascii wide
                        $string30_p0wnedShell_offensive_tool_keyword = "H4sIAAAAAAAEANy9e3wTVfo4PG1SmkLbCdpgFdSgUeuCbLTAthYk005gQhNahUIVkCqIqKi1TaAuIGBaJRzG27Kuul5wV3fV1fUuUFxNKbTl3oJAuaiouE4paAGBFpB5n" nocase ascii wide
                        $string31_p0wnedShell_offensive_tool_keyword = "H4sIAAAAAAAEAO06C3Bb1ZVXjp4t23HkOJZx4ji8BDk2UDuOFcD5mEixBM9UpiJxUgYSZEV" nocase ascii wide
                        $string32_p0wnedShell_offensive_tool_keyword = "H4sIAAAAAAAEAO1YfXRTR3YfWZItGxkrxE4cwodI5Bg2sS35yZ" nocase ascii wide
                        $string33_p0wnedShell_offensive_tool_keyword = "Invoke-BloodHound -CollectionMethod" nocase ascii wide
                        $string34_p0wnedShell_offensive_tool_keyword = /Invoke\-PowerShellTcpOneLine\.ps1/ nocase ascii wide
                        $string35_p0wnedShell_offensive_tool_keyword = "net localgroup administrators BadAss /add" nocase ascii wide
                        $string36_p0wnedShell_offensive_tool_keyword = "net user BadAss FacePalm01 /add" nocase ascii wide
                        $string37_p0wnedShell_offensive_tool_keyword = "oHD9EjJcITqhVYleFRX47sNLtKx6gWnG8wU0iaP5C1pdSrbMuZfBzmyvk23OAQ" nocase ascii wide
                        $string38_p0wnedShell_offensive_tool_keyword = /p0wnedADAttacks\.cs/ nocase ascii wide
                        $string39_p0wnedShell_offensive_tool_keyword = /p0wnedAmsiBypass\.cs/ nocase ascii wide
                        $string40_p0wnedShell_offensive_tool_keyword = /p0wnedAwareness\.cs/ nocase ascii wide
                        $string41_p0wnedShell_offensive_tool_keyword = /p0wnedBinaries\.cs/ nocase ascii wide
                        $string42_p0wnedShell_offensive_tool_keyword = /p0wnedCredentialUI\.cs/ nocase ascii wide
                        $string43_p0wnedShell_offensive_tool_keyword = /p0wnedEasySystem\.cs/ nocase ascii wide
                        $string44_p0wnedShell_offensive_tool_keyword = /p0wnedExecute\.cs/ nocase ascii wide
                        $string45_p0wnedShell_offensive_tool_keyword = /p0wnedExploits\.cs/ nocase ascii wide
                        $string46_p0wnedShell_offensive_tool_keyword = /p0wnedExtensionMethods\.cs/ nocase ascii wide
                        $string47_p0wnedShell_offensive_tool_keyword = /p0wnedHost\.cs/ nocase ascii wide
                        $string48_p0wnedShell_offensive_tool_keyword = /p0wnedHostUserInterface\.cs/ nocase ascii wide
                        $string49_p0wnedShell_offensive_tool_keyword = /p0wnedHostUtilities\.cs/ nocase ascii wide
                        $string50_p0wnedShell_offensive_tool_keyword = /p0wnedInveigh\.cs/ nocase ascii wide
                        $string51_p0wnedShell_offensive_tool_keyword = /P0wnedListener\.Exe/ nocase ascii wide
                        $string52_p0wnedShell_offensive_tool_keyword = /p0wnedListenerConsole\.cs/ nocase ascii wide
                        $string53_p0wnedShell_offensive_tool_keyword = /p0wnedMasq\.cs/ nocase ascii wide
                        $string54_p0wnedShell_offensive_tool_keyword = /p0wnedMeter\.cs/ nocase ascii wide
                        $string55_p0wnedShell_offensive_tool_keyword = /p0wnedMeter\.Menu/ nocase ascii wide
                        $string56_p0wnedShell_offensive_tool_keyword = /p0wnedMov\.cs/ nocase ascii wide
                        $string57_p0wnedShell_offensive_tool_keyword = /p0wnedPELoader\.cs/ nocase ascii wide
                        $string58_p0wnedShell_offensive_tool_keyword = /p0wnedPotato\.cs/ nocase ascii wide
                        $string59_p0wnedShell_offensive_tool_keyword = /p0wnedPowerCat\.cs/ nocase ascii wide
                        $string60_p0wnedShell_offensive_tool_keyword = /p0wnedPPID\.cs/ nocase ascii wide
                        $string61_p0wnedShell_offensive_tool_keyword = /p0wnedRawUserInterface\.cs/ nocase ascii wide
                        $string62_p0wnedShell_offensive_tool_keyword = /p0wnedResources\.cs/ nocase ascii wide
                        $string63_p0wnedShell_offensive_tool_keyword = /p0wnedRoast\.cs/ nocase ascii wide
                        $string64_p0wnedShell_offensive_tool_keyword = "p0wnedShell" nocase ascii wide
                        $string65_p0wnedShell_offensive_tool_keyword = /p0wnedShell\.cs/ nocase ascii wide
                        $string66_p0wnedShell_offensive_tool_keyword = /p0wnedShellx64\.exe/ nocase ascii wide
                        $string67_p0wnedShell_offensive_tool_keyword = /p0wnedShellx86\.exe/ nocase ascii wide
                        $string68_p0wnedShell_offensive_tool_keyword = /p0wnedSystem\.cs/ nocase ascii wide
                        $string69_p0wnedShell_offensive_tool_keyword = "PSInvoke_BloodHound" nocase ascii wide
                        $string70_p0wnedShell_offensive_tool_keyword = "root@P0wnedHost" nocase ascii wide
                        $string71_p0wnedShell_offensive_tool_keyword = "ZnVuY3Rpb24gSW52b2tlLVNoZWxsY29kZQ0K" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}