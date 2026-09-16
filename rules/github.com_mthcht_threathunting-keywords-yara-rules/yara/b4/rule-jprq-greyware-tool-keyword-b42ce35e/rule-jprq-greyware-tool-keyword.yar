rule rule_jprq_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'jprq' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jprq"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_jprq_greyware_tool_keyword = /\sjprq\-windows\-386\.exe/ nocase ascii wide
                        $string2_jprq_greyware_tool_keyword = /\sjprq\-windows\-amd64\.exe/ nocase ascii wide
                        $string3_jprq_greyware_tool_keyword = /\/etc\/letsencrypt\/live\/jprq\.site\//
                        $string4_jprq_greyware_tool_keyword = /\/jprq\.git/ nocase ascii wide
                        $string5_jprq_greyware_tool_keyword = /\/jprq\.log/
                        $string6_jprq_greyware_tool_keyword = /\/jprq\.service/
                        $string7_jprq_greyware_tool_keyword = /\/jprq\/server\/.{0,100}\.go/
                        $string8_jprq_greyware_tool_keyword = "/jprq-darwin-arm64"
                        $string9_jprq_greyware_tool_keyword = "/jprq-linux-386"
                        $string10_jprq_greyware_tool_keyword = "/jprq-linux-arm64"
                        $string11_jprq_greyware_tool_keyword = /\/jprq\-windows\-386\.exe/ nocase ascii wide
                        $string12_jprq_greyware_tool_keyword = /\/jprq\-windows\-amd64\.exe/ nocase ascii wide
                        $string13_jprq_greyware_tool_keyword = "/root/jprq-server"
                        $string14_jprq_greyware_tool_keyword = "/usr/local/bin/jprq"
                        $string15_jprq_greyware_tool_keyword = "/var/log/jprq/"
                        $string16_jprq_greyware_tool_keyword = /\\jprq\-windows\-386\.exe/ nocase ascii wide
                        $string17_jprq_greyware_tool_keyword = /\\jprq\-windows\-amd64\.exe/ nocase ascii wide
                        $string18_jprq_greyware_tool_keyword = ">jprq - join public router" nocase ascii wide
                        $string19_jprq_greyware_tool_keyword = "01713b6ae56ab0f1faf7834f29c22fb36c41bef9c6cf2b702dc3f617513c3be6" nocase ascii wide
                        $string20_jprq_greyware_tool_keyword = "0cfa716d39fc90ed0c4db1bd68f1b4b791f26e5fab4003ae9b816d1f7d68d208" nocase ascii wide
                        $string21_jprq_greyware_tool_keyword = "0d05bed47cc1579a068f83123a502c59d447b20a5318c1d70ffb7a0b638a7aff" nocase ascii wide
                        $string22_jprq_greyware_tool_keyword = "1a1b2883ad2c55fe3a1d4544bc1401e92a0b98148d85f6e5fdaa54154ba5a2e8" nocase ascii wide
                        $string23_jprq_greyware_tool_keyword = "1b41fb4be93b92548f9e5419fae45b76592a5b6ab0c5d42930f6824686225f3c" nocase ascii wide
                        $string24_jprq_greyware_tool_keyword = "1e68cb8928288f31a3f1b7fc867f79f56912c289f93a3dffd962fea895fb8f12" nocase ascii wide
                        $string25_jprq_greyware_tool_keyword = "2ed85cb524b3d21a29ae39ad50874d1cf8546d2dfedb931b9fcf76cc4e0e7cf0" nocase ascii wide
                        $string26_jprq_greyware_tool_keyword = "31fb5154969f2729699b04a7ea6202ad59dabb1e36eb5f8f9b1159e3775e267f" nocase ascii wide
                        $string27_jprq_greyware_tool_keyword = "3984e827963ca5f0925404d02526b0c12956f4d04a64853226e54a2f9333bf04" nocase ascii wide
                        $string28_jprq_greyware_tool_keyword = "3eaa14907c96c3a261cce8f5379fa8ecab9911cc2f3711b4b08b8d382a7ee772" nocase ascii wide
                        $string29_jprq_greyware_tool_keyword = "4796c4183abeeb96966e3eb03493345cd7e148688e9fe5613c5bda26692063b7" nocase ascii wide
                        $string30_jprq_greyware_tool_keyword = "51e63f127dfc4804bec4dc1e5bc19034d50953c246417203b95ddba89bbfe082" nocase ascii wide
                        $string31_jprq_greyware_tool_keyword = "5a19b174e1c46c7f3591c79dc5264d43bb68c9537393a8cecd6269567b821778" nocase ascii wide
                        $string32_jprq_greyware_tool_keyword = "6c3dc714596f1b78c4921bb8b25f073bdc95a8bca363f070b4e5e34c4b2a34ac" nocase ascii wide
                        $string33_jprq_greyware_tool_keyword = "73314bd200038dc11b2a008f9d90164565d15744724a5ea9a0750823a8d0d73b" nocase ascii wide
                        $string34_jprq_greyware_tool_keyword = "7d367e348e24f197222c639324ce56bea8d2b2cd39c88f8df390e1b5af90942b" nocase ascii wide
                        $string35_jprq_greyware_tool_keyword = "8e63f8fb62f2dd2f310bf619ab65c97d5dd1835d97cced5eb8cebddd293d2d06" nocase ascii wide
                        $string36_jprq_greyware_tool_keyword = "905bda9ca65d9b7f6151de763a7c3ce2dd15a69b8410d89b04dd5bb68d17dece" nocase ascii wide
                        $string37_jprq_greyware_tool_keyword = "9e3476f783250e1fd848c17fb9d5a6c32e151ff1382bcde09a0ac903dea8a16f" nocase ascii wide
                        $string38_jprq_greyware_tool_keyword = "a56d443310f333dae0b4900ca18d0f903f5076369ae4053c035d9c39d76f59b2" nocase ascii wide
                        $string39_jprq_greyware_tool_keyword = "acd19845a6484eee65db6f925b1d0244300831d4d5a37d147cc61e7e8c56775b" nocase ascii wide
                        $string40_jprq_greyware_tool_keyword = "azimjohn/jprq" nocase ascii wide
                        $string41_jprq_greyware_tool_keyword = "b44c1910df6b24847b75712e9f183d5fd9119e2e4dfdc15eeecb5e7159e4530a" nocase ascii wide
                        $string42_jprq_greyware_tool_keyword = "bdca5844eac154b94bbdd1b51e68f7d4e45a560fa13c7ce0a227646b0091982a" nocase ascii wide
                        $string43_jprq_greyware_tool_keyword = "bf356e9c87e06eddfe9c5c476742bbc9cf26405631296f03c8f57f91afbb5247" nocase ascii wide
                        $string44_jprq_greyware_tool_keyword = "de10b700cffb64956f55e044a9ce830d9b775af10560b54f21b2fc125c801618" nocase ascii wide
                        $string45_jprq_greyware_tool_keyword = "e749b296484dbb4329fc0e4dff5fe963ddc7ff3450042ce267fdd1b5abcd2fdb" nocase ascii wide
                        $string46_jprq_greyware_tool_keyword = "f11f0d5b7f14d4751f40b9c2c92928dfdbe0d055981e140ba0a5d75ecfe72e10" nocase ascii wide
                        $string47_jprq_greyware_tool_keyword = "fc621d5952a8fb61bfc73e197db64d87f35d1c12550b7bf6160bc78f6d61e44f" nocase ascii wide
                        $string48_jprq_greyware_tool_keyword = /github\.com.{0,100}\/jprq\/releases\/download\// nocase ascii wide
                        $string49_jprq_greyware_tool_keyword = /https\:\/\/aur\.archlinux\.org\/jprq\.git/
                        $string50_jprq_greyware_tool_keyword = /https\:\/\/jprq\.io\/auth/ nocase ascii wide
                        $string51_jprq_greyware_tool_keyword = /https\:\/\/jprq\.io\/install\.sh/ nocase ascii wide
                        $string52_jprq_greyware_tool_keyword = "JPRQ - The Tunneling Service" nocase ascii wide
                        $string53_jprq_greyware_tool_keyword = "jprq is successfully installed" nocase ascii wide
                        $string54_jprq_greyware_tool_keyword = "JPRQ_DOMAIN=" nocase ascii wide
                        $string55_jprq_greyware_tool_keyword = /MIIEpQIBAAKCAQEAuIGT1C2uPwb62IT\/5IJdFioVAB\/r3Pa885n4z\+xEtGIm6XmD/ nocase ascii wide
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