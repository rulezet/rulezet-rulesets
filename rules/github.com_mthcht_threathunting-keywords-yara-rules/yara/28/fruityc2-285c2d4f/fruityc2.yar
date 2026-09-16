rule FruityC2
{
    meta:
        description = "Detection patterns for the tool 'FruityC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FruityC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -DumpCreds -ComputerName " nocase ascii wide
                        $string2 = " -ServiceName VulnSVC " nocase ascii wide
                        $string3 = /\/fruityc2\.crt/
                        $string4 = /\/FruityC2\.git/ nocase ascii wide
                        $string5 = /\/fruityc2\.key/
                        $string6 = /\/fruityc2\.pem/
                        $string7 = /\/FruityC2\/archive\/master\.zip/ nocase ascii wide
                        $string8 = "/FruityC2/releases/" nocase ascii wide
                        $string9 = "/FruityC2-Client" nocase ascii wide
                        $string10 = /\\FruityC2\-Client/ nocase ascii wide
                        $string11 = /\\ps_encoder\.py/ nocase ascii wide
                        $string12 = /\\ps_proxy\.ps1/ nocase ascii wide
                        $string13 = /\\ps_stager\.ps1/ nocase ascii wide
                        $string14 = /\\PSReflect\.psm1/ nocase ascii wide
                        $string15 = "<H1>PowerUp report for " nocase ascii wide
                        $string16 = "<H2>Vulnerabl Schasks" nocase ascii wide
                        $string17 = "028648d9410d8aaf65b7cb4999999947b55f8aa4db3ec24ff82b601b77ecc335" nocase ascii wide
                        $string18 = "069a9a0aece20ae241fe75e4ba6e1338f8292bf9510182883f649a32fe27604c" nocase ascii wide
                        $string19 = "21fff74c2464be8072328345721555138aed7e15adc531ae4f244820a0f3061f" nocase ascii wide
                        $string20 = "2e0680b916b117d6eff7e621212b7ac6f28c41b95a3fc18b91b13922e3e2e72f" nocase ascii wide
                        $string21 = "39f719f490cdea6b7566c0ad99a6c70b6d241f80328a82a403f33468a91744f2" nocase ascii wide
                        $string22 = "3a87abf646b679217d7c67e45c5df4bac7b3ea9f5e33ccd7ad82b964d0bc73a7" nocase ascii wide
                        $string23 = "40b10d676e40a4c5c006f2d8b92cd5fa069b83348612d052e626e7792b4edbf7" nocase ascii wide
                        $string24 = "4260354c3960e04e73b36289099665ce1cb839d1c56696639e782643c98dbe7b" nocase ascii wide
                        $string25 = "488785c691425b7cb3c355b1ae38a0527faf339f68a3536f34e1ee10c627790c" nocase ascii wide
                        $string26 = "4f5f8bd4df664f10dbd919129bbf7d8c6c8a02da74b36a20c322b5a1ce257249" nocase ascii wide
                        $string27 = "5241f01eb654fe100e0c2a973b7f2443e7bcd914e5b388cc07031871a7d4d199" nocase ascii wide
                        $string28 = "55b47d76298d6f56ea19a06c6bab41145675717159890d4787fe83c8785bbf23" nocase ascii wide
                        $string29 = "5f346d82d780b573ffd6e4ae1051dd96d10d5141d17535d5538ae8713096085b" nocase ascii wide
                        $string30 = "6cc72a74c01d04cf06cca303ba6a584a4261829d88fde64592e5a04cb0a16522" nocase ascii wide
                        $string31 = "7af03cf989ce48137cd2b74c1020fc42241d7dea7ffaf6ff67f16a23a302ad80" nocase ascii wide
                        $string32 = "99f14934d82a3db78f0f68017c079ec04dedddc5890bf5ce5194dd30801f779d" nocase ascii wide
                        $string33 = "a71ca78d1c4b0dc8d6c35c883b18034a5b505886cc74fed0003c5e095494b1c8" nocase ascii wide
                        $string34 = "adaptivethreat/Empire" nocase ascii wide
                        $string35 = "b4af4df46eb9a169f197c093325d983db5dc0ab1eb6bd7aa67458e4f48c2e0b2" nocase ascii wide
                        $string36 = /Create\sSSL\scertificate\s\(FruityC2\)/ nocase ascii wide
                        $string37 = "dec9c3346c770a93bd7f1fb1b891100d806ecc70f1c5da84ea001aa0efb3694d" nocase ascii wide
                        $string38 = "Downloading AD-Recon PS scripts" nocase ascii wide
                        $string39 = "Downloading Empire PS scripts" nocase ascii wide
                        $string40 = "Downloading FruityC2" nocase ascii wide
                        $string41 = "Downloading Nishang PS scripts" nocase ascii wide
                        $string42 = "Downloading PowerSploit PS scripts" nocase ascii wide
                        $string43 = "e1966d7c2abe5f6f610c745858ab19a48b1b4ee7db738e15f4bb8b1009f38eb9" nocase ascii wide
                        $string44 = "e35cdc81954fb9701b5fd2f79300a5a6b2dd018e82aa733727a734b08ddd9715" nocase ascii wide
                        $string45 = "eeba4c8ec806378fecc51fb7ffe3b48c5fa57108330b822043494cc4cea99d89" nocase ascii wide
                        $string46 = /FruityC2\.py/ nocase ascii wide
                        $string47 = /Get\-ExploitableSystem\.psm1/ nocase ascii wide
                        $string48 = /Get\-ExploitableSystems\.psm1/ nocase ascii wide
                        $string49 = /Get\-PassHashes\.ps1/ nocase ascii wide
                        $string50 = /Get\-Screenshot\.ps1/ nocase ascii wide
                        $string51 = /Get\-SPN\-FruityC2\.ps1/ nocase ascii wide
                        $string52 = /http\:\/\/127\.0\.0\.1\:50000\/payload\/upload/ nocase ascii wide
                        $string53 = "Invoke-ACLScanner" nocase ascii wide
                        $string54 = "Invoke-CheckLocalAdminAccess -ComputerName " nocase ascii wide
                        $string55 = "Invoke-EnumerateLocalAdmin" nocase ascii wide
                        $string56 = "Invoke-FileFinder -ShareList " nocase ascii wide
                        $string57 = "Invoke-FruityC2" nocase ascii wide
                        $string58 = "Invoke-ImpersonateUser" nocase ascii wide
                        $string59 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
                        $string60 = "Invoke-PatchDll -DllBytes " nocase ascii wide
                        $string61 = "invoke-reflectivedllinjection-ps1" nocase ascii wide
                        $string62 = "Invoke-ServiceAbuse" nocase ascii wide
                        $string63 = "Invoke-StealthUserHunter " nocase ascii wide
                        $string64 = /Invoke\-TokenManipulation\.ps1/ nocase ascii wide
                        $string65 = /PostExploitation\.psm1/ nocase ascii wide
                        $string66 = /powershell\-import\s\/var\/www\/ps\/.{0,100}\.ps1/ nocase ascii wide
                        $string67 = /PowerUp\.ps1/ nocase ascii wide
                        $string68 = /PowerView\.ps1/ nocase ascii wide
                        $string69 = "PyroTek3/PowerShell-AD-Recon" nocase ascii wide
                        $string70 = "samratashok/nishang" nocase ascii wide
                        $string71 = /standard\:\:base64.{0,100}kerberos\:\:list\s\/export/ nocase ascii wide
                        $string72 = "Write-HijackDll -OutputFile" nocase ascii wide
                        $string73 = "xtr4nge/FruityC2" nocase ascii wide
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