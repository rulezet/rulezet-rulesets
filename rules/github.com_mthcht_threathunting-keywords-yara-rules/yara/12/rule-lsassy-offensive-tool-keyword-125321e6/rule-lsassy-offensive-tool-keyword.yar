rule rule_lsassy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lsassy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsassy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lsassy_offensive_tool_keyword = " - Remote lsass dump reader" nocase ascii wide
                        $string2_lsassy_offensive_tool_keyword = /\scomsvcs_stealth\.py/ nocase ascii wide
                        $string3_lsassy_offensive_tool_keyword = /\sDEL\s\{\}SQLDmpr.{0,1000}\.mdmp\s\&\sfor\s\/f\s/ nocase ascii wide
                        $string4_lsassy_offensive_tool_keyword = /\sdllinject\.py/ nocase ascii wide
                        $string5_lsassy_offensive_tool_keyword = " dump --usermode --kernelmode --driver " nocase ascii wide
                        $string6_lsassy_offensive_tool_keyword = /\sdumpert\.py/ nocase ascii wide
                        $string7_lsassy_offensive_tool_keyword = /\s\-\-dump\-name\s.{0,1000}lsass/ nocase ascii wide
                        $string8_lsassy_offensive_tool_keyword = /\s\-fullmemdmp\s\-snap\s\&\sping\s127\.0\.0\.1\s\-n\s/ nocase ascii wide
                        $string9_lsassy_offensive_tool_keyword = /\simpacketfile\.py/ nocase ascii wide
                        $string10_lsassy_offensive_tool_keyword = " lsassy" nocase ascii wide
                        $string11_lsassy_offensive_tool_keyword = /\srawrpc_embedded\.py/ nocase ascii wide
                        $string12_lsassy_offensive_tool_keyword = /\sSQLDmpr0001\.mdmp/ nocase ascii wide
                        $string13_lsassy_offensive_tool_keyword = /\/\.config\/lsassy/
                        $string14_lsassy_offensive_tool_keyword = /\/comsvcs_stealth\.py/ nocase ascii wide
                        $string15_lsassy_offensive_tool_keyword = /\/dllinject\.py/ nocase ascii wide
                        $string16_lsassy_offensive_tool_keyword = /\/dumpert\.py/ nocase ascii wide
                        $string17_lsassy_offensive_tool_keyword = /\/dumpmethod\/.{0,1000}\.py/ nocase ascii wide
                        $string18_lsassy_offensive_tool_keyword = /\/impacketfile\.py/ nocase ascii wide
                        $string19_lsassy_offensive_tool_keyword = "/lsassy" nocase ascii wide
                        $string20_lsassy_offensive_tool_keyword = "/lsassy/releases/download/" nocase ascii wide
                        $string21_lsassy_offensive_tool_keyword = /\/rawrpc\.py/ nocase ascii wide
                        $string22_lsassy_offensive_tool_keyword = /\/rawrpc_embedded\.py/ nocase ascii wide
                        $string23_lsassy_offensive_tool_keyword = /\/silentprocessexit\.py/ nocase ascii wide
                        $string24_lsassy_offensive_tool_keyword = /\/tmp\/credentials\.txt/
                        $string25_lsassy_offensive_tool_keyword = "/tmp/kerberos_tickets"
                        $string26_lsassy_offensive_tool_keyword = /\\comsvcs_stealth\.py/ nocase ascii wide
                        $string27_lsassy_offensive_tool_keyword = /\\dllinject\.py/ nocase ascii wide
                        $string28_lsassy_offensive_tool_keyword = /\\dumpert\.py/ nocase ascii wide
                        $string29_lsassy_offensive_tool_keyword = /\\impacketfile\.py/ nocase ascii wide
                        $string30_lsassy_offensive_tool_keyword = /\\rawrpc_embedded\.py/ nocase ascii wide
                        $string31_lsassy_offensive_tool_keyword = /\\temp\\lsass\.exe/ nocase ascii wide
                        $string32_lsassy_offensive_tool_keyword = "049ab1e5eef6dbfb0cfe81f8eac287d82db549369edf2992916d9c8109528159" nocase ascii wide
                        $string33_lsassy_offensive_tool_keyword = "0bed6254a9818d22f531a9433f9b20d31eefe0550ece4ba12f4e05e8db5c2cfb" nocase ascii wide
                        $string34_lsassy_offensive_tool_keyword = "0e3c7a01a06f011d9bb7e184d4713f88bbb3def0118e70e2f58ca79966b7c067" nocase ascii wide
                        $string35_lsassy_offensive_tool_keyword = "16df73e36a53fb2a7c2a022c36d999a853c3e616ae4de7c3633a8d7769e81ec5" nocase ascii wide
                        $string36_lsassy_offensive_tool_keyword = "216767025356ffaa54815bf698254810253efcd10feddfab82e7f6ed991d553c" nocase ascii wide
                        $string37_lsassy_offensive_tool_keyword = "21870c033ee041fa83e39818f3f23a51c1f994344f15f1f2b95912c013ad77ff" nocase ascii wide
                        $string38_lsassy_offensive_tool_keyword = "21db0a4b79dc31e1a31251fd69d793e6dd4839e3a869093f8abd8bc10aa4b7fb" nocase ascii wide
                        $string39_lsassy_offensive_tool_keyword = "221986c87ed18ec810267b11b919766d2d556127d9a4f2b16f544b39a32c8573" nocase ascii wide
                        $string40_lsassy_offensive_tool_keyword = "22df0e3fcbba509c1e28a0df720e8a36b62f731ee3bf6066dbd2d6ed09592052" nocase ascii wide
                        $string41_lsassy_offensive_tool_keyword = "2dc0932b1ec1f7be50038ddcfc69790ff8b8db824d0121a02aad709a9a92119f" nocase ascii wide
                        $string42_lsassy_offensive_tool_keyword = "31a97e6377d69a3ae7974a441d52657d200210087bfcac7f0c4f79dddf9f488b" nocase ascii wide
                        $string43_lsassy_offensive_tool_keyword = "37754362c1524cbecc907a1cde4a3c4e1c747235a140c2275e482724fca9955d" nocase ascii wide
                        $string44_lsassy_offensive_tool_keyword = "3a7f12e2da6e68b00f1a0aff9b515e7c623da2304f729ed756e01582ddfb62aa" nocase ascii wide
                        $string45_lsassy_offensive_tool_keyword = "3f0aaab9ed83635ff24bf9664603d16e9130183bdb15f55dd02b92d760a97833" nocase ascii wide
                        $string46_lsassy_offensive_tool_keyword = "417f4c1ad7f0f15d3c01d4930cc583330eb93cf71593c8d872b65a2a50cbb6fc" nocase ascii wide
                        $string47_lsassy_offensive_tool_keyword = "4841539dd633e3c38767c9098481406113d80aba6c23e5326f30e5328ac30234" nocase ascii wide
                        $string48_lsassy_offensive_tool_keyword = "4bb963704e0b986784a5d5b1ad7cc6daffc7e062fedf0025df4974e8b0478602" nocase ascii wide
                        $string49_lsassy_offensive_tool_keyword = "51fecfd2da4eb46257e94548af984f53d88be1e8d476ef0bc64a801588dbb6b5" nocase ascii wide
                        $string50_lsassy_offensive_tool_keyword = "580ec64c62709841ca04ba73473f1e8681fde57ebbbbb81d1fe12b075b263057" nocase ascii wide
                        $string51_lsassy_offensive_tool_keyword = "5a9b8cfd138823a0d9799afc9eb70f28ec2ede90a1db1fde81d8bd70e5613fba" nocase ascii wide
                        $string52_lsassy_offensive_tool_keyword = "5aaed5c8657383a894443a92a259182d9dc2c01de72a80460fff4a636e20c65b" nocase ascii wide
                        $string53_lsassy_offensive_tool_keyword = "78177028fe6c048b40b90f696adfdcbcbda0a7c9f678125bbead5b4f116098fc" nocase ascii wide
                        $string54_lsassy_offensive_tool_keyword = "7971e955309e5158aa13fe774596224af88ae64e53f09bd2ffb863acbf88864a" nocase ascii wide
                        $string55_lsassy_offensive_tool_keyword = "7eb2d2b7d0eaf25f822afa65e9887683ad2c1dd48c2cc447a76a6526222acf06" nocase ascii wide
                        $string56_lsassy_offensive_tool_keyword = "8560ec462441496a3bd6b0266ed1b023cdb1870a190aaa9dbb34ffcc6e6dd281" nocase ascii wide
                        $string57_lsassy_offensive_tool_keyword = "87582936adeabd882de92613193a3fefdc2d388238a7c67c3bb41666ac3b2dda" nocase ascii wide
                        $string58_lsassy_offensive_tool_keyword = "8b5b0e03d4d5becb309f86a7149dd0573f89c19bcd4f8becb7d86b17c90a6c04" nocase ascii wide
                        $string59_lsassy_offensive_tool_keyword = "8bc52fc1dbd2e9319241d826b23a227132199b37951c8222c901b6ab069c4084" nocase ascii wide
                        $string60_lsassy_offensive_tool_keyword = "9aeafd043bc6edebba1acbf6f457a63be0edd623899f6245b71ac2e7ba61e03d" nocase ascii wide
                        $string61_lsassy_offensive_tool_keyword = "9c08b2701019c0b4860a85af161c64c303400d720c494aaeade5c2d0d2607118" nocase ascii wide
                        $string62_lsassy_offensive_tool_keyword = "b3d7df3faa7bbeddf70a0c3cb586ce3d38aa1bfd787da67dd2338ec72a27bb74" nocase ascii wide
                        $string63_lsassy_offensive_tool_keyword = "b9d705378ce1af446cc51bbbeccdda2d05bbc6b3c9249f3b69661d5f763dafaa" nocase ascii wide
                        $string64_lsassy_offensive_tool_keyword = "bad0968b9492c3161ea9b67ecf8520054f90e6d196a7ea0050c8076b2ed2d2a2" nocase ascii wide
                        $string65_lsassy_offensive_tool_keyword = "c7b633d9ffcddd84074219649dae082184e2331c07b395db5e2ffa9abe316355" nocase ascii wide
                        $string66_lsassy_offensive_tool_keyword = "cb8f501c3b38552612b6303dfec0479df31b9c79a5fbec5462614f9a1d7eba67" nocase ascii wide
                        $string67_lsassy_offensive_tool_keyword = "cc8ca4e1e0d6613bd6f040f098f59ff05cea4b9ca74262ec7319ce9846e51a6e" nocase ascii wide
                        $string68_lsassy_offensive_tool_keyword = "d583e8ee91ab53e8c797b3beb22bfb8b9e775f88436798225e2ec361832a8942" nocase ascii wide
                        $string69_lsassy_offensive_tool_keyword = "d9e58e0a47eacc9ccb42322516dcd21658aedb39e1dd64ff4af86e4fca648ddc" nocase ascii wide
                        $string70_lsassy_offensive_tool_keyword = /dllinject\.py/ nocase ascii wide
                        $string71_lsassy_offensive_tool_keyword = /dump_lsass\(/ nocase ascii wide
                        $string72_lsassy_offensive_tool_keyword = /dumpert\.py/ nocase ascii wide
                        $string73_lsassy_offensive_tool_keyword = "dumpert_path=" nocase ascii wide
                        $string74_lsassy_offensive_tool_keyword = "dumpertdll" nocase ascii wide
                        $string75_lsassy_offensive_tool_keyword = /dumpertdll\.py/ nocase ascii wide
                        $string76_lsassy_offensive_tool_keyword = "e71c92b2228f78010d91f373ea3c1ed474c0b6298c3b9615edf9edb42be35abb" nocase ascii wide
                        $string77_lsassy_offensive_tool_keyword = "e82a6a97f9239b0e6bd68c9ce795dc7ae29f6e008bfb8ab63f2dfe9e94817bea" nocase ascii wide
                        $string78_lsassy_offensive_tool_keyword = /edrsandblast\.py/ nocase ascii wide
                        $string79_lsassy_offensive_tool_keyword = "faf7eccc7aa509a6ac4b65b15e5bd91101a21ec9dd519b9917e7f0ce5f9191e5" nocase ascii wide
                        $string80_lsassy_offensive_tool_keyword = "ff7db32d94ef4b9e11ced9226a8e4a62eb0ec932e66b4655b845dd7f717bf94a" nocase ascii wide
                        $string81_lsassy_offensive_tool_keyword = /for\s\/f\s\\"\\"tokens\=2\sdelims\=\s\\"\\"\s\%.{0,1000}tasklist\s\/fi\s\\"\\"Imagename\seq\slsass\.exe/ nocase ascii wide
                        $string82_lsassy_offensive_tool_keyword = /hackndo\@gmail\.com/ nocase ascii wide
                        $string83_lsassy_offensive_tool_keyword = /https\:\/\/en\.hackndo\.com\/remote\-lsass\-dump\-passwords\// nocase ascii wide
                        $string84_lsassy_offensive_tool_keyword = /impacketfile\.py/ nocase ascii wide
                        $string85_lsassy_offensive_tool_keyword = "login-securite/lsassy" nocase ascii wide
                        $string86_lsassy_offensive_tool_keyword = "login-securite/lsassy" nocase ascii wide
                        $string87_lsassy_offensive_tool_keyword = "lsassy " nocase ascii wide
                        $string88_lsassy_offensive_tool_keyword = /lsassy\./ nocase ascii wide
                        $string89_lsassy_offensive_tool_keyword = /lsassy\.impacketfile/ nocase ascii wide
                        $string90_lsassy_offensive_tool_keyword = "lsassy/dumpmethod" nocase ascii wide
                        $string91_lsassy_offensive_tool_keyword = "lsassy_linux_amd64"
                        $string92_lsassy_offensive_tool_keyword = /lsassy_logger\./ nocase ascii wide
                        $string93_lsassy_offensive_tool_keyword = "lsassy_windows_amd64" nocase ascii wide
                        $string94_lsassy_offensive_tool_keyword = "lsassy-linux-x64-"
                        $string95_lsassy_offensive_tool_keyword = "lsassy-MacOS-x64-" nocase ascii wide
                        $string96_lsassy_offensive_tool_keyword = /lsassy\-windows\-latest\.zip/ nocase ascii wide
                        $string97_lsassy_offensive_tool_keyword = /lsassy\-windows\-x64\-.{0,1000}\.exe/ nocase ascii wide
                        $string98_lsassy_offensive_tool_keyword = "-m dumpert " nocase ascii wide
                        $string99_lsassy_offensive_tool_keyword = /mirrordump\.py/ nocase ascii wide
                        $string100_lsassy_offensive_tool_keyword = /nanodump\./ nocase ascii wide
                        $string101_lsassy_offensive_tool_keyword = "nanodump_ssp" nocase ascii wide
                        $string102_lsassy_offensive_tool_keyword = /nanodump_ssp_embedded\./ nocase ascii wide
                        $string103_lsassy_offensive_tool_keyword = "pip install lsassy" nocase ascii wide
                        $string104_lsassy_offensive_tool_keyword = /ppldump\.py/ nocase ascii wide
                        $string105_lsassy_offensive_tool_keyword = "ppldump_embedded" nocase ascii wide
                        $string106_lsassy_offensive_tool_keyword = "procdump_embedded" nocase ascii wide
                        $string107_lsassy_offensive_tool_keyword = "procdump_path=" nocase ascii wide
                        $string108_lsassy_offensive_tool_keyword = /rdrleakdiag\.exe\s\-p\s\(Get\-Process\slsass\)/ nocase ascii wide
                        $string109_lsassy_offensive_tool_keyword = /rdrleakdiag\.py/ nocase ascii wide
                        $string110_lsassy_offensive_tool_keyword = /smb_stealth\.py/ nocase ascii wide
                        $string111_lsassy_offensive_tool_keyword = /sqldumper\.py/ nocase ascii wide
                        $string112_lsassy_offensive_tool_keyword = /test_lsassy\./ nocase ascii wide

    condition:
        any of them
}