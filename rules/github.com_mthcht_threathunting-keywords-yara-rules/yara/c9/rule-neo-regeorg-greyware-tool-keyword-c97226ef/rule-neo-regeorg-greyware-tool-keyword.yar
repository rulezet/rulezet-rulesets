rule rule_Neo_reGeorg_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Neo-reGeorg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Neo-reGeorg"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Neo_reGeorg_greyware_tool_keyword = /\sneoreg\.py\s/ nocase ascii wide
                        $string2_Neo_reGeorg_greyware_tool_keyword = /\.py\s.{0,100}\-\-proxy\ssocks5\:\/\// nocase ascii wide
                        $string3_Neo_reGeorg_greyware_tool_keyword = /\/neoreg\.py/ nocase ascii wide
                        $string4_Neo_reGeorg_greyware_tool_keyword = /\/Neo\-reGeorg\.git/ nocase ascii wide
                        $string5_Neo_reGeorg_greyware_tool_keyword = /\/NeoreGeorg\.java/ nocase ascii wide
                        $string6_Neo_reGeorg_greyware_tool_keyword = "/Neo-reGeorg/tarball" nocase ascii wide
                        $string7_Neo_reGeorg_greyware_tool_keyword = "/Neo-reGeorg/zipball" nocase ascii wide
                        $string8_Neo_reGeorg_greyware_tool_keyword = /\/tunnel\.nosocket\.php/ nocase ascii wide
                        $string9_Neo_reGeorg_greyware_tool_keyword = /\[Ask\sNeoGeorg\]\sNeoGeorg\s/ nocase ascii wide
                        $string10_Neo_reGeorg_greyware_tool_keyword = "005f37654d164e5605ad7180a7af68d82da9b747e6fed34b71f6fda0883e6f74" nocase ascii wide
                        $string11_Neo_reGeorg_greyware_tool_keyword = "01f7bb1226ad5d0c68b39ab60014b9e9f55ef85c56be7b0faed70d67bfbc13e5" nocase ascii wide
                        $string12_Neo_reGeorg_greyware_tool_keyword = "0a539ea3eb8e7708241c05a746cf459f027e1bb4ab54e870bbcbe63e3f7a6de9" nocase ascii wide
                        $string13_Neo_reGeorg_greyware_tool_keyword = "0f0c16e48d436603eff91f1a31043abb24df99f91a26ff8e73577d45b1152de5" nocase ascii wide
                        $string14_Neo_reGeorg_greyware_tool_keyword = "10a63c922b6d9bec0f3b7a8d755a01b815d81556eb93f2526db0b5a36c597d6e" nocase ascii wide
                        $string15_Neo_reGeorg_greyware_tool_keyword = "10d4bd7d47330656a50ba2557cd66ed93ea8a0010ef366f34b1a5e20e159297b" nocase ascii wide
                        $string16_Neo_reGeorg_greyware_tool_keyword = "11c11bef98644223da8b9e1242b046e58a04a844b6c6a6fb88b7818f296ecdb3" nocase ascii wide
                        $string17_Neo_reGeorg_greyware_tool_keyword = "12324526e79390f63e86cb9b7cebd7029d8da32fc2f73f2486517d0b451da60f" nocase ascii wide
                        $string18_Neo_reGeorg_greyware_tool_keyword = "213ace4b0c02f038549af071ee3e0033da7e88cd8f809d257b4c9b2dc81b9f4d" nocase ascii wide
                        $string19_Neo_reGeorg_greyware_tool_keyword = "2fdef205058424a234864a4f77be2f451f1e52608781fb0ec10fdf867d2b4dfb" nocase ascii wide
                        $string20_Neo_reGeorg_greyware_tool_keyword = "32ea3247b4e572e80e116ae9a9ffb122c0766b0cc546c6122dab07da5aefde16" nocase ascii wide
                        $string21_Neo_reGeorg_greyware_tool_keyword = "3c139c9ae721f89e61a98294cb486143ee435297beff1a6178cc7347b4ff278e" nocase ascii wide
                        $string22_Neo_reGeorg_greyware_tool_keyword = "3d735de00aeb9535224e29d0adb6f2fefc79b7a46f76702af0d8eebcd49c1772" nocase ascii wide
                        $string23_Neo_reGeorg_greyware_tool_keyword = "43791d1689cb309eac4e6e9748f86decf655732c3790d10ec2d30962900d52e2" nocase ascii wide
                        $string24_Neo_reGeorg_greyware_tool_keyword = "478256ef0c35f13ada15baea0dd8a7e09c40ef2ff2e0a54a83681d920b93ba8a" nocase ascii wide
                        $string25_Neo_reGeorg_greyware_tool_keyword = "56bf15ccd413e54239dde9103fa9e0bdbdfd5f3788855dbfec3fbe0e6a003b98" nocase ascii wide
                        $string26_Neo_reGeorg_greyware_tool_keyword = "585ed5d6cb415cd94af39825a85dfec415f92249a8d57b5a6159537720958f42" nocase ascii wide
                        $string27_Neo_reGeorg_greyware_tool_keyword = "5a5cbc0b756cbda7a9ac64ca5a0ad33899bd3ea9ae42113389c230a164900b74" nocase ascii wide
                        $string28_Neo_reGeorg_greyware_tool_keyword = "5ab3fd2f7133bb9d297ebdfda1c2cf7af45baf3149b7d29932202e2ccb79c21f" nocase ascii wide
                        $string29_Neo_reGeorg_greyware_tool_keyword = "695626bd1c10bf40379744a91ceefd71c27261b26b959d87de5c2ec74bced1a4" nocase ascii wide
                        $string30_Neo_reGeorg_greyware_tool_keyword = "6c4a877eb0a3bc495d7490c2f218678005a10cd6e978a92c497791b980ca8567" nocase ascii wide
                        $string31_Neo_reGeorg_greyware_tool_keyword = "7cde37e49b52a6ea480783c572a2fd04afcae330251ac65bbbc77b1c37faca6b" nocase ascii wide
                        $string32_Neo_reGeorg_greyware_tool_keyword = "7ea80cfb998032be5b67dc614fc40087e1e36383e59a46616c9d03405c08af3c" nocase ascii wide
                        $string33_Neo_reGeorg_greyware_tool_keyword = "806ad9ce802f8e110440ed228eddc40d82dad33ca0feaae1530d1490edb34d90" nocase ascii wide
                        $string34_Neo_reGeorg_greyware_tool_keyword = "807ed1ebbac824f29a84235afe7522ddbb66bf392a7c1f5ea849a5f0aedf1d20" nocase ascii wide
                        $string35_Neo_reGeorg_greyware_tool_keyword = "82fab464a4b0e1f1e284ec32370edd5090637c682ba7e7e609f2f5bb95c78c4b" nocase ascii wide
                        $string36_Neo_reGeorg_greyware_tool_keyword = "8cc5a818d4db91362257001f7bb7995841bf3d83bc8d91e16a4329797b937cac" nocase ascii wide
                        $string37_Neo_reGeorg_greyware_tool_keyword = "92e23b3baec268e8b8eea8833e0d1aa5c2cf337ca20be4ceb2880d8aaaf89d4a" nocase ascii wide
                        $string38_Neo_reGeorg_greyware_tool_keyword = "9a468a1e3f8e645593dc25d5cb45d6b640da574e07afcc518e07eb1738a68510" nocase ascii wide
                        $string39_Neo_reGeorg_greyware_tool_keyword = "9aa4b36654c9a2d7883a745ab791bcfc723ddcf793c4109529c1b8d8bbea41f0" nocase ascii wide
                        $string40_Neo_reGeorg_greyware_tool_keyword = "9fc57548ab7ea8aed9b35ff5a6ceee11afd5707139f98333381fcc1442bc45aa" nocase ascii wide
                        $string41_Neo_reGeorg_greyware_tool_keyword = "a10a179116e873452ca3323ce17ae870ea2a240c754b696dcfd3442e7bbc16a7" nocase ascii wide
                        $string42_Neo_reGeorg_greyware_tool_keyword = "a3f949008272bef1ec57519e2417f80fcdfcb633eda2c0c0e102062ffe37e62f" nocase ascii wide
                        $string43_Neo_reGeorg_greyware_tool_keyword = "a7c3d70099b1df9cb3165a8b5885fa727a778f3b3526811c0b5f16c30dccc492" nocase ascii wide
                        $string44_Neo_reGeorg_greyware_tool_keyword = "aa244cce94120eeaef5bb7aa7e11a129662a50ecd4a0d542ae4a425b5757daf7" nocase ascii wide
                        $string45_Neo_reGeorg_greyware_tool_keyword = "ab7eed3ed5928eb01b0676183186172a6a23711c645ba6f97081efaf3b0d2fec" nocase ascii wide
                        $string46_Neo_reGeorg_greyware_tool_keyword = "b0c4f83b23c0bd366537a33642050c0ddfb4184d969dbf2e934903873a801953" nocase ascii wide
                        $string47_Neo_reGeorg_greyware_tool_keyword = "b2b717b196a443ae5421b0e6cb1656d29034ede9c604bf04fec2bddaeba5dcf8" nocase ascii wide
                        $string48_Neo_reGeorg_greyware_tool_keyword = "baf1e7bdd6feedd6b9144fed16093bd281ce26dc0da57137a5385fc7a5fc498f" nocase ascii wide
                        $string49_Neo_reGeorg_greyware_tool_keyword = "c09e5a6ac3d8fb135b20e08d1550b54ea0ea84da2bcdaf2dbfa739f607804b88" nocase ascii wide
                        $string50_Neo_reGeorg_greyware_tool_keyword = "c4183ce1d991cb27ef71b811f373222759494d1cf1db55dccce83405d0d570d3" nocase ascii wide
                        $string51_Neo_reGeorg_greyware_tool_keyword = "c938afbd5c475a7071dbc1912a4b5c211f7c8bbbae1c2389989c2115a08d7a0d" nocase ascii wide
                        $string52_Neo_reGeorg_greyware_tool_keyword = "cacc832d9daf18d621c26497f5affd8b6b27cf5e34332b8bd95da127efdbb5e1" nocase ascii wide
                        $string53_Neo_reGeorg_greyware_tool_keyword = "cb183ce9401cd7ad838bedb22fb49717d5de7da10b8f64781aceb4912d6f5ec8" nocase ascii wide
                        $string54_Neo_reGeorg_greyware_tool_keyword = "cc1a1ea3b0a719e36037ca340e24d6d574324578267bdfc38c3b4710289ec578" nocase ascii wide
                        $string55_Neo_reGeorg_greyware_tool_keyword = "cc284e9b0925fd814e4aa3d125804f7cde054863c3c467492a14e8f73a4cbced" nocase ascii wide
                        $string56_Neo_reGeorg_greyware_tool_keyword = "cd152f7de2ba0b3fc2e6053141b7bf326bca81aed5d5efa709bb10baa801cdd2" nocase ascii wide
                        $string57_Neo_reGeorg_greyware_tool_keyword = "cm9vdDppcyB0d2VsdmU=" nocase ascii wide
                        $string58_Neo_reGeorg_greyware_tool_keyword = "d77577b4a183167f9e8b5f798e3f71fa4f41c81d1db9ce37c68bb6decfbdf737" nocase ascii wide
                        $string59_Neo_reGeorg_greyware_tool_keyword = "d80046ee572c3222790560fc51c02de131507d5425bed6cecca98bc3f3ca50e9" nocase ascii wide
                        $string60_Neo_reGeorg_greyware_tool_keyword = "dc57b353d32389a0af8a7ccb2054633ac502d899bb5bc9e656e91849215a57a1" nocase ascii wide
                        $string61_Neo_reGeorg_greyware_tool_keyword = "debbc69c2926f0062b8243a484cd5710c6ba290f738e26a6e6ff403c3a536843" nocase ascii wide
                        $string62_Neo_reGeorg_greyware_tool_keyword = "e10eff3227d730806c99dc8ac0f38a2262ed5ab3a86d90b4acb7efbb2d6d2def" nocase ascii wide
                        $string63_Neo_reGeorg_greyware_tool_keyword = "e7836e1d44fe8ea29276fba8ea5fd5c94a242c2ec8d04850a62625c7792bff46" nocase ascii wide
                        $string64_Neo_reGeorg_greyware_tool_keyword = "e9894baec4b491e0ee3bce3a760b33546ee03270f9ea6155f5dbebd66d820c11" nocase ascii wide
                        $string65_Neo_reGeorg_greyware_tool_keyword = "f7b6475de06cdecd9b187a735bb3f960fa56bc12c7205225e0550dd7a7814a34" nocase ascii wide
                        $string66_Neo_reGeorg_greyware_tool_keyword = "f7c1d9613d4f4a7d5cc193f7a52c83aa3be1abf466de9ef0a9e2b2faaa846a69" nocase ascii wide
                        $string67_Neo_reGeorg_greyware_tool_keyword = "fa2f44b31d65e2b907ad9a3e1ddf95d9aac53905b53ff2bfeb178a7746b0cafe" nocase ascii wide
                        $string68_Neo_reGeorg_greyware_tool_keyword = "fdaaa6bd9cbb9875b35f339dbd7b7481bc3aef2e2eb59caa2b77ffbd34ed079b" nocase ascii wide
                        $string69_Neo_reGeorg_greyware_tool_keyword = "L-codes/Neo-reGeorg" nocase ascii wide
                        $string70_Neo_reGeorg_greyware_tool_keyword = "NeoGeorg says, 'All seems fine'" nocase ascii wide
                        $string71_Neo_reGeorg_greyware_tool_keyword = /neoreg\.py\sgenerate/ nocase ascii wide
                        $string72_Neo_reGeorg_greyware_tool_keyword = /neoreg\.py\s\-k\s.{0,100}\s\-u\shttp.{0,100}\.php/ nocase ascii wide
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