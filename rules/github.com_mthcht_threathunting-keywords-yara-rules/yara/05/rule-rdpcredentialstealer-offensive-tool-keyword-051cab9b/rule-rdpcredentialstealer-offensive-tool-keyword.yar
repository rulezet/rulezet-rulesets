rule rule_RDPCredentialStealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RDPCredentialStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPCredentialStealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RDPCredentialStealer_offensive_tool_keyword = /\/RDPCredentialStealer\.git/ nocase ascii wide
                        $string2_RDPCredentialStealer_offensive_tool_keyword = "/RDPCredentialStealer/releases/download/" nocase ascii wide
                        $string3_RDPCredentialStealer_offensive_tool_keyword = "/RDPCredentialStealer/tarball/latest" nocase ascii wide
                        $string4_RDPCredentialStealer_offensive_tool_keyword = /\:\\Users\\Public\\Music\\.{0,100}\.dll/ nocase ascii wide
                        $string5_RDPCredentialStealer_offensive_tool_keyword = /\\bin\\HostX64\\x64\\c2\.dll/ nocase ascii wide
                        $string6_RDPCredentialStealer_offensive_tool_keyword = /\\Public\\Music\\RDPCreds\.txt/ nocase ascii wide
                        $string7_RDPCredentialStealer_offensive_tool_keyword = /\\RDPCreds\.txt/ nocase ascii wide
                        $string8_RDPCredentialStealer_offensive_tool_keyword = /\\RDPCredsStealerDLL/ nocase ascii wide
                        $string9_RDPCredentialStealer_offensive_tool_keyword = "118c2a7d06f9ac1aabdec653f236e04f3a697f59bef6f4e9c9ca1ea8acdc33db" nocase ascii wide
                        $string10_RDPCredentialStealer_offensive_tool_keyword = "118c2a7d06f9ac1aabdec653f236e04f3a697f59bef6f4e9c9ca1ea8acdc33db" nocase ascii wide
                        $string11_RDPCredentialStealer_offensive_tool_keyword = "2eeba6742b716b69144db95b0240d6d7a50d48f28f2dec83b003e74ff4958ad1" nocase ascii wide
                        $string12_RDPCredentialStealer_offensive_tool_keyword = "33d0f399-f79a-44a2-a487-21fce657be35" nocase ascii wide
                        $string13_RDPCredentialStealer_offensive_tool_keyword = "4358d271e8e3db49fc9ba98ab0709727f9043a129b5978ebaa23881f60b26b64" nocase ascii wide
                        $string14_RDPCredentialStealer_offensive_tool_keyword = "5eabd7d957e56a9cb9a918f7e9f72dc76a0481954c2f93ad5264095b5dbb6897" nocase ascii wide
                        $string15_RDPCredentialStealer_offensive_tool_keyword = "5eabd7d957e56a9cb9a918f7e9f72dc76a0481954c2f93ad5264095b5dbb6897" nocase ascii wide
                        $string16_RDPCredentialStealer_offensive_tool_keyword = "5eabd7d957e56a9cb9a918f7e9f72dc76a0481954c2f93ad5264095b5dbb6897" nocase ascii wide
                        $string17_RDPCredentialStealer_offensive_tool_keyword = "78fa6d6f41b506791944c470b4cceb3af184a9c6fcaa804d706763cb9c29b52b" nocase ascii wide
                        $string18_RDPCredentialStealer_offensive_tool_keyword = "7ef6a655e0c09263822565e5022ff3bd33494f1bedc2062862f769ebd2c93897" nocase ascii wide
                        $string19_RDPCredentialStealer_offensive_tool_keyword = /APIHookInjectorBin\.exe/ nocase ascii wide
                        $string20_RDPCredentialStealer_offensive_tool_keyword = /APIHookInjectorBin\.log/ nocase ascii wide
                        $string21_RDPCredentialStealer_offensive_tool_keyword = /APIHookInjectorBin\.pdb/ nocase ascii wide
                        $string22_RDPCredentialStealer_offensive_tool_keyword = /APIHookInjectorBin\.sln/ nocase ascii wide
                        $string23_RDPCredentialStealer_offensive_tool_keyword = "e8930c16d171577f55aa0cbdd8fe5fe656bba46751cd44e2e2fda325b6f6e9b9" nocase ascii wide
                        $string24_RDPCredentialStealer_offensive_tool_keyword = "ea17314d15bea466526ba9ca154009f04f46da461899ac4533d00479317703b8" nocase ascii wide
                        $string25_RDPCredentialStealer_offensive_tool_keyword = "ec2aaff0-b349-4855-9093-96acf6ee3299" nocase ascii wide
                        $string26_RDPCredentialStealer_offensive_tool_keyword = /RDPCredentialStealer\.zip/ nocase ascii wide
                        $string27_RDPCredentialStealer_offensive_tool_keyword = "RDPCredentialStealer-main" nocase ascii wide
                        $string28_RDPCredentialStealer_offensive_tool_keyword = /RDPCredsStealerDLL\./ nocase ascii wide
                        $string29_RDPCredentialStealer_offensive_tool_keyword = /RDPCredsStealerDLL\.dll/ nocase ascii wide
                        $string30_RDPCredentialStealer_offensive_tool_keyword = "S12cybersecurity/RDPCredentialStealer" nocase ascii wide
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