rule rule_godoh_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'godoh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "godoh"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_godoh_offensive_tool_keyword = /\/cmd\/c2\.go/ nocase ascii wide
                        $string2_godoh_offensive_tool_keyword = /\/goDoH\.git/ nocase ascii wide
                        $string3_godoh_offensive_tool_keyword = /\/godoh\.git/ nocase ascii wide
                        $string4_godoh_offensive_tool_keyword = "/godoh/" nocase ascii wide
                        $string5_godoh_offensive_tool_keyword = "/goDoH/releases" nocase ascii wide
                        $string6_godoh_offensive_tool_keyword = /\/godoh\-master\.zip/ nocase ascii wide
                        $string7_godoh_offensive_tool_keyword = /\\godoh\\cmd\\/ nocase ascii wide
                        $string8_godoh_offensive_tool_keyword = /\\godoh\\dnsclient\\/ nocase ascii wide
                        $string9_godoh_offensive_tool_keyword = /\\godoh\\dnsserver/ nocase ascii wide
                        $string10_godoh_offensive_tool_keyword = /\\godoh\\lib\\/ nocase ascii wide
                        $string11_godoh_offensive_tool_keyword = /\\godoh\\protocol\\/ nocase ascii wide
                        $string12_godoh_offensive_tool_keyword = "11f51e1a8f1a630390533599cfbcb78133d680f6" nocase ascii wide
                        $string13_godoh_offensive_tool_keyword = "2589213f0c51583dcbaacbe0005e5908" nocase ascii wide
                        $string14_godoh_offensive_tool_keyword = "26953f6a9ae961392ed1484e9c7ace1211f5f962" nocase ascii wide
                        $string15_godoh_offensive_tool_keyword = "27e71eebac244f803d825159fe3b1971c9bfb169" nocase ascii wide
                        $string16_godoh_offensive_tool_keyword = "300875180931c7f9f62908e72395f992510eea9e" nocase ascii wide
                        $string17_godoh_offensive_tool_keyword = "4045eef04cb934ac996942d0d51e80420b2ba985" nocase ascii wide
                        $string18_godoh_offensive_tool_keyword = "438bf6db9eece197ef8d3e133a7e229086b5682d" nocase ascii wide
                        $string19_godoh_offensive_tool_keyword = "4caedf29083d75d0d6687f56981fda77cce0849f" nocase ascii wide
                        $string20_godoh_offensive_tool_keyword = "558df705dd4b6213c11e858b7c32960eaec39360" nocase ascii wide
                        $string21_godoh_offensive_tool_keyword = "5e5a0618107570e45d2d2559d13658fb0e08f732" nocase ascii wide
                        $string22_godoh_offensive_tool_keyword = "61254294a879235560c1bcf796ff256bc48d2d90" nocase ascii wide
                        $string23_godoh_offensive_tool_keyword = "61c0af74e23b91ced41254e8d701482a157464d4" nocase ascii wide
                        $string24_godoh_offensive_tool_keyword = "7423162b1a3b77b3cb5f76173204dd5983b683ae" nocase ascii wide
                        $string25_godoh_offensive_tool_keyword = "86445d7ef450ddcb190f14c6f7fc8a1a33945c45" nocase ascii wide
                        $string26_godoh_offensive_tool_keyword = "8fc21bc6c4a11583b4db44e3dad0980bdb5c7ace" nocase ascii wide
                        $string27_godoh_offensive_tool_keyword = "911be80c0cbcc8c3bc351a3e60db0d7494858603" nocase ascii wide
                        $string28_godoh_offensive_tool_keyword = "9bd15de627aa46533968e0f7fae19e8b855d0a40" nocase ascii wide
                        $string29_godoh_offensive_tool_keyword = /A\sDNS\s\(over\-HTTPS\)\sC2/ nocase ascii wide
                        $string30_godoh_offensive_tool_keyword = "aacf6ed6e4b999a6338d5a025350ea5a" nocase ascii wide
                        $string31_godoh_offensive_tool_keyword = "acda6b715fc3fdeed1f43c73e5467f5824093ac0" nocase ascii wide
                        $string32_godoh_offensive_tool_keyword = "ae84192b77cec541a088d563dc5f20723123e096" nocase ascii wide
                        $string33_godoh_offensive_tool_keyword = "b37eeeceb6addc2243bca9c408ee13554726772d" nocase ascii wide
                        $string34_godoh_offensive_tool_keyword = "bb141fb92bcd492552d5d6c09fbf39f7f674eb49" nocase ascii wide
                        $string35_godoh_offensive_tool_keyword = "bd976ca9268513e6cc4a58b85574f62b8a76cc92" nocase ascii wide
                        $string36_godoh_offensive_tool_keyword = "cc9f09bbdb9277265fd71b7575b1fdda3bc2f946" nocase ascii wide
                        $string37_godoh_offensive_tool_keyword = "d162d2e96da627fac5a93d5e6faf379aff092bbd" nocase ascii wide
                        $string38_godoh_offensive_tool_keyword = "d67c342b9ffebd2350cb81d6dbbb35071246fb19" nocase ascii wide
                        $string39_godoh_offensive_tool_keyword = "d9fd35586f323c9990b3da5c7c1f07c05ff88bc7" nocase ascii wide
                        $string40_godoh_offensive_tool_keyword = "e4f33ee9ba4d86685f8df4a89e192a354139edcf" nocase ascii wide
                        $string41_godoh_offensive_tool_keyword = "f27479a8728d9126cc055daeb5cddd01cabfa37d" nocase ascii wide
                        $string42_godoh_offensive_tool_keyword = "f59e403b62053c785de7df979c5cb7b0f426cbeb" nocase ascii wide
                        $string43_godoh_offensive_tool_keyword = "godoh -" nocase ascii wide
                        $string44_godoh_offensive_tool_keyword = "godoh agent" nocase ascii wide
                        $string45_godoh_offensive_tool_keyword = "godoh c2" nocase ascii wide
                        $string46_godoh_offensive_tool_keyword = "godoh --domain" nocase ascii wide
                        $string47_godoh_offensive_tool_keyword = "godoh help" nocase ascii wide
                        $string48_godoh_offensive_tool_keyword = "godoh receive" nocase ascii wide
                        $string49_godoh_offensive_tool_keyword = "godoh send" nocase ascii wide
                        $string50_godoh_offensive_tool_keyword = "godoh test --" nocase ascii wide
                        $string51_godoh_offensive_tool_keyword = "godoh test" nocase ascii wide
                        $string52_godoh_offensive_tool_keyword = /godoh.{0,1000}\s\-\-agent\-name\s.{0,1000}\-\-poll\-time/ nocase ascii wide
                        $string53_godoh_offensive_tool_keyword = /godoh.{0,1000}\s\-\-domain\s.{0,1000}\sc2/ nocase ascii wide
                        $string54_godoh_offensive_tool_keyword = /godoh.{0,1000}\s\-\-domain\s.{0,1000}\sreceive/ nocase ascii wide
                        $string55_godoh_offensive_tool_keyword = /godoh.{0,1000}\s\-\-domain\s.{0,1000}send\s\-\-file\s/ nocase ascii wide
                        $string56_godoh_offensive_tool_keyword = "godoh-darwin64"
                        $string57_godoh_offensive_tool_keyword = "godoh-darwin64"
                        $string58_godoh_offensive_tool_keyword = "godoh-linux64"
                        $string59_godoh_offensive_tool_keyword = "godoh-linux64"
                        $string60_godoh_offensive_tool_keyword = /godoh\-windows32\./ nocase ascii wide
                        $string61_godoh_offensive_tool_keyword = /godoh\-windows32\.exe/ nocase ascii wide
                        $string62_godoh_offensive_tool_keyword = /godoh\-windows64\./ nocase ascii wide
                        $string63_godoh_offensive_tool_keyword = /godoh\-windows64\.exe/ nocase ascii wide
                        $string64_godoh_offensive_tool_keyword = /https\:\/\/dns\.blokada\.org\/dns\-query/ nocase ascii wide
                        $string65_godoh_offensive_tool_keyword = /https\:\/\/dns10\.quad9\.net\:5053\/dns\-query/ nocase ascii wide
                        $string66_godoh_offensive_tool_keyword = /https\:\/\/github\.com\/curl\/curl\/wiki\/DNS\-over\-HTTPS/ nocase ascii wide
                        $string67_godoh_offensive_tool_keyword = "Receive a file via DoH" nocase ascii wide
                        $string68_godoh_offensive_tool_keyword = /Send\sa\sfile\svia\sDoH\./ nocase ascii wide
                        $string69_godoh_offensive_tool_keyword = "sensepost/goDoH" nocase ascii wide
                        $string70_godoh_offensive_tool_keyword = "sensepost/godoh" nocase ascii wide
                        $string71_godoh_offensive_tool_keyword = "Starts the godoh C2 server" nocase ascii wide
                        $string72_godoh_offensive_tool_keyword = "Starts the godoh C2 server" nocase ascii wide
                        $string73_godoh_offensive_tool_keyword = "Tests communications to all of the known DNS-over-HTTPS communications providers" nocase ascii wide

    condition:
        any of them
}