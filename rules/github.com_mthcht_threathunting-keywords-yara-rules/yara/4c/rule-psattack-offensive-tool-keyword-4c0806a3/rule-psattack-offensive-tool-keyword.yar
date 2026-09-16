rule rule_PSAttack_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PSAttack' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAttack"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PSAttack_offensive_tool_keyword = /\/PSAttack\.git/ nocase ascii wide
                        $string2_PSAttack_offensive_tool_keyword = /\/PSAttack\.zip/ nocase ascii wide
                        $string3_PSAttack_offensive_tool_keyword = "/PSAttack/releases/download/" nocase ascii wide
                        $string4_PSAttack_offensive_tool_keyword = /\\attackState\.cmd/ nocase ascii wide
                        $string5_PSAttack_offensive_tool_keyword = /\\DNS\-TXT\-Pwnage\.ps1/ nocase ascii wide
                        $string6_PSAttack_offensive_tool_keyword = /\\Do\-Exfiltration\.ps1/ nocase ascii wide
                        $string7_PSAttack_offensive_tool_keyword = /\\get\-attack\.ps1/ nocase ascii wide
                        $string8_PSAttack_offensive_tool_keyword = /\\Get\-GPPPassword\.ps1/ nocase ascii wide
                        $string9_PSAttack_offensive_tool_keyword = /\\Get\-WLAN\-Keys\.ps1/ nocase ascii wide
                        $string10_PSAttack_offensive_tool_keyword = /\\Gupt\-Backdoor\.ps1/ nocase ascii wide
                        $string11_PSAttack_offensive_tool_keyword = /\\Inveigh\.ps1/ nocase ascii wide
                        $string12_PSAttack_offensive_tool_keyword = /\\Invoke\-MS16\-032\.ps1/ nocase ascii wide
                        $string13_PSAttack_offensive_tool_keyword = /\\Invoke\-PsUACme\.ps1/ nocase ascii wide
                        $string14_PSAttack_offensive_tool_keyword = /\\Powercat\.ps1/ nocase ascii wide
                        $string15_PSAttack_offensive_tool_keyword = /\\PowerUp\.ps1/ nocase ascii wide
                        $string16_PSAttack_offensive_tool_keyword = /\\PSAttack\.sln/ nocase ascii wide
                        $string17_PSAttack_offensive_tool_keyword = /\\PSAttack\.zip/ nocase ascii wide
                        $string18_PSAttack_offensive_tool_keyword = "06e22309431bcbf87df30bb1b6e971b0edfe05f7f466f87e9c9982c3e4715bc5" nocase ascii wide
                        $string19_PSAttack_offensive_tool_keyword = "0d4ab1674ad2b13652979d996a41f55a353eb2f32f854a95c7068e66c072f63c" nocase ascii wide
                        $string20_PSAttack_offensive_tool_keyword = "1316ca67af20db4bc3b47218855dfd47d9075f0a72bb681821f70af4fdce6f5c" nocase ascii wide
                        $string21_PSAttack_offensive_tool_keyword = "17893a44c856de700187251711368a3393fa79c92b65d39eb6eb56718a78c255" nocase ascii wide
                        $string22_PSAttack_offensive_tool_keyword = "1d70076be53e454fdb7dda0570961920e6bfe2d11ab0080064e206dd20c83333" nocase ascii wide
                        $string23_PSAttack_offensive_tool_keyword = "1e8fc1ed166a78bcb9075d3cd122af35d3bcca902a842bde00a0c6d515820cfa" nocase ascii wide
                        $string24_PSAttack_offensive_tool_keyword = "2103fd114d530753c7eadd8561d76ed952863c9d58a64ecf6b3abb160f863db1" nocase ascii wide
                        $string25_PSAttack_offensive_tool_keyword = "3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2" nocase ascii wide
                        $string26_PSAttack_offensive_tool_keyword = "4621d400f556301fd9ba40c1325a65727b4eb564eeda5fb0368f547eec603ff3" nocase ascii wide
                        $string27_PSAttack_offensive_tool_keyword = "4b8997973189f7f85b4c2ad8fd3320269481d70b70c67046d0994844e5fb852a" nocase ascii wide
                        $string28_PSAttack_offensive_tool_keyword = "565d4502e4f8d24a2bf76a7cffdf27b54604b8211c3986ae05fa75bb46d8b356" nocase ascii wide
                        $string29_PSAttack_offensive_tool_keyword = "5e77fa12d0f1b9a4a7249a6a496f8236552bc0adcbe818d9e997e1ca68819224" nocase ascii wide
                        $string30_PSAttack_offensive_tool_keyword = "830023999e063bef7fd09709d0aa3e34eb0cce2dacd382f381350e8890b20dee" nocase ascii wide
                        $string31_PSAttack_offensive_tool_keyword = "89d37b998b4dde0492d237508a2521a79768d284f8d184a017fcbe444393307c" nocase ascii wide
                        $string32_PSAttack_offensive_tool_keyword = "8cOpc1mnZbcpRkvRwqE8jeEvQdxxO67SVM6GP8rLbDdePzAzLVTbI23DCQCaMIgo" nocase ascii wide
                        $string33_PSAttack_offensive_tool_keyword = "929cc2194f0dff4b6b8e7102e841253dfbdca6790f45e0f1165fbdbeeffc390a" nocase ascii wide
                        $string34_PSAttack_offensive_tool_keyword = "a75c79d0fbcc1c76214625d2924fa60e2c74bf8b4b40bf191a1f68a4b28e748d" nocase ascii wide
                        $string35_PSAttack_offensive_tool_keyword = "a834a0a0c5e0d0ef14de2e986b53b032747f52071815957e42633495fb7bc42f" nocase ascii wide
                        $string36_PSAttack_offensive_tool_keyword = "ae18dc1b4124abbbd1eaff296cedaa2e8d6ef2ad1070b537f1963355cd1cd769" nocase ascii wide
                        $string37_PSAttack_offensive_tool_keyword = "c664a81f5833fc705151ebee4e25084e6a2c7315ad1324245460aaae5ed9d065" nocase ascii wide
                        $string38_PSAttack_offensive_tool_keyword = "c6e3cbe978095e155f6fafe6028c2f6a0a6e156a46d3473fb795c701ead2fd0b" nocase ascii wide
                        $string39_PSAttack_offensive_tool_keyword = /ConvertFrom\-CSV\s\$attacksCSV/ nocase ascii wide
                        $string40_PSAttack_offensive_tool_keyword = /Could\snot\srun\sAMSI\sbypass\./ nocase ascii wide
                        $string41_PSAttack_offensive_tool_keyword = "d1d533085ee36aee9b817636d6ed5323da22461af7de88b016484610531c6f0e" nocase ascii wide
                        $string42_PSAttack_offensive_tool_keyword = "DA1B7904-0DDC-45A0-875F-33BBA2236C44" nocase ascii wide
                        $string43_PSAttack_offensive_tool_keyword = "e06104b2d8e8ba207a916352e2f49e4d03f6b0c3bb04d5703e71037ff279ec4d" nocase ascii wide
                        $string44_PSAttack_offensive_tool_keyword = "e8bba4503b2e26b62002980969dc7a3d1dbe1699c4ce054929692704600b33ba" nocase ascii wide
                        $string45_PSAttack_offensive_tool_keyword = "e94cb3644275a5675abf5146e368ec04147570db966781014bf320c921ccbfd2" nocase ascii wide
                        $string46_PSAttack_offensive_tool_keyword = "ecf242b41a845439cc80e76710718b3162be13aee4c7abfa153a5e913c0f4767" nocase ascii wide
                        $string47_PSAttack_offensive_tool_keyword = "f2935c9643fbbf76da73f5218cf6a8b299b4252247d81060f8d7d12f146bd69d" nocase ascii wide
                        $string48_PSAttack_offensive_tool_keyword = "GDSSecurity/PSAttack" nocase ascii wide
                        $string49_PSAttack_offensive_tool_keyword = "Get-Attack -term " nocase ascii wide
                        $string50_PSAttack_offensive_tool_keyword = /Invoke\-MetasploitPayload\.ps1/ nocase ascii wide
                        $string51_PSAttack_offensive_tool_keyword = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
                        $string52_PSAttack_offensive_tool_keyword = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
                        $string53_PSAttack_offensive_tool_keyword = /Invoke\-mimikittenz\.ps1/ nocase ascii wide
                        $string54_PSAttack_offensive_tool_keyword = /Invoke\-MS16\-032\.ps1/ nocase ascii wide
                        $string55_PSAttack_offensive_tool_keyword = "Invoke-NinjaCopy" nocase ascii wide
                        $string56_PSAttack_offensive_tool_keyword = /Invoke\-PsUACme\.ps1/ nocase ascii wide
                        $string57_PSAttack_offensive_tool_keyword = /Invoke\-Shellcode\.ps1/ nocase ascii wide
                        $string58_PSAttack_offensive_tool_keyword = /Invoke\-WMICommand\.ps1/ nocase ascii wide
                        $string59_PSAttack_offensive_tool_keyword = "jaredhaight/PSAttackBuildTool" nocase ascii wide
                        $string60_PSAttack_offensive_tool_keyword = "KexMnyvBHcpAfniIdwPEXIgPdlxiUNMrYkSMrnXcdVOYYeoscIbuQssBxijBANhu" nocase ascii wide
                        $string61_PSAttack_offensive_tool_keyword = /PowerView\.ps1/ nocase ascii wide
                        $string62_PSAttack_offensive_tool_keyword = "PSAttack" nocase ascii wide
                        $string63_PSAttack_offensive_tool_keyword = /PSAttack\.exe/ nocase ascii wide
                        $string64_PSAttack_offensive_tool_keyword = /PSAttack\.Resources\.BuildDate\.txt/ nocase ascii wide
                        $string65_PSAttack_offensive_tool_keyword = /VolumeShadowCopyTools\.ps1/ nocase ascii wide
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