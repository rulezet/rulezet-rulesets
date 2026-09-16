rule rule_traitor_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'traitor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "traitor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_traitor_offensive_tool_keyword = /\/gtfobins\.go/
                        $string2_traitor_offensive_tool_keyword = /\/tmp\/traitor\.so/
                        $string3_traitor_offensive_tool_keyword = "/traitor/pkg/backdoor"
                        $string4_traitor_offensive_tool_keyword = "/traitor/releases/download/"
                        $string5_traitor_offensive_tool_keyword = "/traitor-386"
                        $string6_traitor_offensive_tool_keyword = "/traitor-amd64"
                        $string7_traitor_offensive_tool_keyword = "/traitor-arm64"
                        $string8_traitor_offensive_tool_keyword = /\|base64\s\-d\s\>\s\/tmp\/traitor/
                        $string9_traitor_offensive_tool_keyword = "01cf2c956d813b4dddcde5f3349ada814764aa45d9579e8dde063c891f62d1d4"
                        $string10_traitor_offensive_tool_keyword = "03fdcd35cfb237327c0813ce931a62ffcf837302f8e0285ff1c8085ee30f2828"
                        $string11_traitor_offensive_tool_keyword = "05c10f59c21e200d25112a44581eab14d4793bfdc4f4cad8a9e6b0d231f4f1aa"
                        $string12_traitor_offensive_tool_keyword = "0d8cac6cbe2019d99a5260f4c934d9a4c9c7022d141006cfc0f87fdc3f8ae4ab"
                        $string13_traitor_offensive_tool_keyword = "1189360f7da03490a9f0f3ce283d487335a4db24232d6fabfd17bc7ec4e53392"
                        $string14_traitor_offensive_tool_keyword = "1312202e1f36db3f8bb319c6a886ba558373b83dd9d8bd54a8fc42ae156d81cb"
                        $string15_traitor_offensive_tool_keyword = "17914e2d97784ef7aaf52f9f8b04db77cad036308c6b3584fa0fa172ad1da077"
                        $string16_traitor_offensive_tool_keyword = "20b948d35e9e730e5aaa00f8de01107af773b93313fed752ae63afcd45353073"
                        $string17_traitor_offensive_tool_keyword = "348980f606af2f76e3fb4ac9e1e66f3eb42da0091e72695942a3e97ff7977c0b"
                        $string18_traitor_offensive_tool_keyword = "3cb401fdba1a0e74389ac9998005805f1d3e8ed70018d282f5885410d48725e1"
                        $string19_traitor_offensive_tool_keyword = "48a7984aefe898990b83d8d8ed16f8e8116288fd7531affa4726b262ba3e682c"
                        $string20_traitor_offensive_tool_keyword = "49a2c7f9b752b7592cb1726d5427c81cb54e4055ef8350226dbb46a32d8fd560"
                        $string21_traitor_offensive_tool_keyword = "4b9e2f5e4582b162aee0241e31482b2a50eb34712b13d2911726b3b988ccdfeb"
                        $string22_traitor_offensive_tool_keyword = "4e1531d35b504cd39a927b3f3dab61a7d8642b405e5f999ff52fa47381e0caa6"
                        $string23_traitor_offensive_tool_keyword = "4e1531d35b504cd39a927b3f3dab61a7d8642b405e5f999ff52fa47381e0caa6"
                        $string24_traitor_offensive_tool_keyword = "53b439d28020a437a1d940fb4c9525283c8093326c1c187da245282e840ba0a4"
                        $string25_traitor_offensive_tool_keyword = "53ef079f580e806d9fae5fd698616574623fd44467c446540ba1194c20c6c388"
                        $string26_traitor_offensive_tool_keyword = "57681a07f437b52ecf05f2b1a6f268c5d3596c9627280d3ddc2750a20b7d5dcf"
                        $string27_traitor_offensive_tool_keyword = "57eda2366c187ce90c39a4710ff1fe62a7d667d25bf9ba63dbe34bf44b0ff684"
                        $string28_traitor_offensive_tool_keyword = "614998828e6d1205980fde58932c9485346edf8e3565669b9a30977d4b952b08"
                        $string29_traitor_offensive_tool_keyword = "68538ddd64073d5e6b9edf092c7a364c0380734826a00bc10e12a7cdc370410a"
                        $string30_traitor_offensive_tool_keyword = "6e08212071f8b95216a56d0a5edef8fbf23cd33f212762a236060c486f9319d0"
                        $string31_traitor_offensive_tool_keyword = "73e0810037eaca1b0a643396b61a0b6462582d89d952c0c20f96f800dbf5e2e5"
                        $string32_traitor_offensive_tool_keyword = "774f93b89388143ef4f6a9752b171f3a337bf7523b236e6719703a239d56cab2"
                        $string33_traitor_offensive_tool_keyword = "8093f462616ec9e222eb6dac9abcff21a6dca3075283e7daca3d209e81cb85f6"
                        $string34_traitor_offensive_tool_keyword = "8093f462616ec9e222eb6dac9abcff21a6dca3075283e7daca3d209e81cb85f6"
                        $string35_traitor_offensive_tool_keyword = "8ace2f6b59f88eea47c07022c330c7fc91811d1a9f39148a3212f844a2dcd9a4"
                        $string36_traitor_offensive_tool_keyword = "8c038621b5807a443d8bf7344f1df9defe0e8193a55efdda8b0e08d0923c3c9e"
                        $string37_traitor_offensive_tool_keyword = "8e0accdd48e1d04e3693326de2750b1e68f75fde6e012dc195cb876088704bdb"
                        $string38_traitor_offensive_tool_keyword = "92d8a70870f02f8bb284a317c9801cc774dfabc2660efea327049289f5137376"
                        $string39_traitor_offensive_tool_keyword = "93cbbd682b981bee01388710acf813b64db918b54b61039d3fe1e019dad077df"
                        $string40_traitor_offensive_tool_keyword = "94f93f559533afd33b026849ee730d3c360faa4e9dcf7241d3d3132802736ee0"
                        $string41_traitor_offensive_tool_keyword = "a12141ccddd231b9596e3ded58b95835338ff5f5fbc0b9470788e51fe9b4e651"
                        $string42_traitor_offensive_tool_keyword = "a46d2986f634a23bf7156290284914da2c25c35b9484c11e119cb2c2f5bd5c08"
                        $string43_traitor_offensive_tool_keyword = "a58a13faa35a214b12f57674937f8ebf27eb62e29e26b7a00a624cc127197b50"
                        $string44_traitor_offensive_tool_keyword = "abdfd724cc84b4f7c2fdd641acfc2427baad0e6eb6c031a53e0c25b17ebb550b"
                        $string45_traitor_offensive_tool_keyword = "b3a161043abbacb0b787da084f3222a1d3432aaff6f9fd16a244a42747ab6d8f"
                        $string46_traitor_offensive_tool_keyword = "b3da8fb4ec21437e3a9b7118e9eb2da1a3b83fa202e546c64533d40e719263d7"
                        $string47_traitor_offensive_tool_keyword = "b5072f210606f0fcf08e88c188e92ed4df8a35b1811008262401b664268f1f6f"
                        $string48_traitor_offensive_tool_keyword = "b88377088eef28045877c620f1a713356ce155885a61b073d3f4569675bda0e7"
                        $string49_traitor_offensive_tool_keyword = /backdoor\/traitor\.go/
                        $string50_traitor_offensive_tool_keyword = "bc99c9d2b150645abdb37d35c032dab28f5995d505294b0bd2c633525c91c4b0"
                        $string51_traitor_offensive_tool_keyword = "c56e66d683919054d0ae34f15f5d08624ad6a8c211ba8768fb52d09190b0a74d"
                        $string52_traitor_offensive_tool_keyword = "c702fa1d6618739e09cfb8e8cb79d563b1da757539bbee812748a79a0624e271"
                        $string53_traitor_offensive_tool_keyword = "c87966a280098a45c90dac27666f3f01f6b6999e7b08719a8035f1355d696ad4"
                        $string54_traitor_offensive_tool_keyword = "d0c376cd617a39f0aae2ad7dd76c689025f894e3682c6e192ed6ff984ae81fd7"
                        $string55_traitor_offensive_tool_keyword = "d2cb266890e46c37292349b26bff380e5a1b2ab09ec20b04a530bbfb0252fdc8"
                        $string56_traitor_offensive_tool_keyword = "d42f35102915099261b206a59fd3e7262af7a6d7f749f2236ba8b6d2349eec92"
                        $string57_traitor_offensive_tool_keyword = "d4e5da3ad9dcf854a1d6d71805fcaf8d418cbb3c7916d85ae641d88a745c23e8"
                        $string58_traitor_offensive_tool_keyword = "d639357536f4da8d953172982a82a87c028a8fb3e4e89307ebff92f5d6c99287"
                        $string59_traitor_offensive_tool_keyword = "d7dc358e43314be5c096f1f011947f422a12a261db64528bb531418eab164638"
                        $string60_traitor_offensive_tool_keyword = "d8309dbfb648a5f80ac88634ffaa3a9d613cd31a785b9902a687edbc2d71d73b"
                        $string61_traitor_offensive_tool_keyword = "dc2dd05cc2f6dea85f0bfc16b0e1008687a32fd92f49f0043ca60a061fd59c66"
                        $string62_traitor_offensive_tool_keyword = "e74bb25e61d959049d06ff838d2147b291dcffe3e96ad0af68077cd9f50d2e82"
                        $string63_traitor_offensive_tool_keyword = "e842c810b6ecb9c7634f1cfbf81b6245094528ac5584179eb8e6932eaa34f421"
                        $string64_traitor_offensive_tool_keyword = "e9a83a9f298baefdcb73e870ad9ec7253247bfa3b7450113c2b5a63e26a8b4ee"
                        $string65_traitor_offensive_tool_keyword = "eaf50935fba5aec83bbdf8fdc1ee57284098b88503c25fab1581d4c2b5ddb41e"
                        $string66_traitor_offensive_tool_keyword = "f04a52623464ec2eb52b22e7348993bf5b7456714505f87342781b8d21c7233c"
                        $string67_traitor_offensive_tool_keyword = "f1452a47c21f37e9d581f706dce8862a1d4d045033470c4080809fb4a205e42c"
                        $string68_traitor_offensive_tool_keyword = "f666dbab003b377019955f3f304ac68c9af5defd5e05a39e916e7af8ad9076c1"
                        $string69_traitor_offensive_tool_keyword = "f833fdd261a1135db87bf4e5cac17447a2d837f6b43513bffae389cc8a8ae00e"
                        $string70_traitor_offensive_tool_keyword = "f91025122cd3b0f537db1eac70c44250530f34ea7521750bb4af7ff1c7af3b8c"
                        $string71_traitor_offensive_tool_keyword = "fcf965a77c9f97dcd7304a7abbe6af09c3e41855c888db2acebfc995365d1a28"
                        $string72_traitor_offensive_tool_keyword = "fdfbfc07248c3359d9f1f536a406d4268f01ed63a856bd6cef9dccb3cf4f2376"
                        $string73_traitor_offensive_tool_keyword = "fe44d88aa5c763905fc4a7b600ac6545f9d169eca637796e28a08a432969f5bc"
                        $string74_traitor_offensive_tool_keyword = /go\sget\s\-u\s.{0,100}traitor\/cmd\/traitor/
                        $string75_traitor_offensive_tool_keyword = "liamg/traitor"
                        $string76_traitor_offensive_tool_keyword = "traitor -a "
                        $string77_traitor_offensive_tool_keyword = "traitor --any "
                        $string78_traitor_offensive_tool_keyword = "traitor -e "
                        $string79_traitor_offensive_tool_keyword = "traitor -e polkit"
                        $string80_traitor_offensive_tool_keyword = "traitor --exploit"
                        $string81_traitor_offensive_tool_keyword = "traitor -p "
                        $string82_traitor_offensive_tool_keyword = "traitor-amd64 upload"
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