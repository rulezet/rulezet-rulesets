rule rule_boringproxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'boringproxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "boringproxy"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_boringproxy_greyware_tool_keyword = /\sboringproxy\-client\.service/ nocase ascii wide
                        $string2_boringproxy_greyware_tool_keyword = /\sboringproxy\-server\.service/ nocase ascii wide
                        $string3_boringproxy_greyware_tool_keyword = " -m boringproxy" nocase ascii wide
                        $string4_boringproxy_greyware_tool_keyword = /\.\/boringproxy\sserver/
                        $string5_boringproxy_greyware_tool_keyword = "/bin/boringproxy"
                        $string6_boringproxy_greyware_tool_keyword = /\/boringproxy\.git/ nocase ascii wide
                        $string7_boringproxy_greyware_tool_keyword = /\/boringproxy\-client\.service/ nocase ascii wide
                        $string8_boringproxy_greyware_tool_keyword = /\/boringproxy\-server\.service/ nocase ascii wide
                        $string9_boringproxy_greyware_tool_keyword = "/home/boringproxy"
                        $string10_boringproxy_greyware_tool_keyword = "/tmp/boringproxy-client"
                        $string11_boringproxy_greyware_tool_keyword = "23d61c88520628dc2ab58b25e556df92640327ca4f946cd8ea30eb813897d107" nocase ascii wide
                        $string12_boringproxy_greyware_tool_keyword = "34362de1defeb018d71e6319afabca362fa4acd69341bfcfb3ce77b6e8c61a6a" nocase ascii wide
                        $string13_boringproxy_greyware_tool_keyword = "403d4848966e4e5e7859758766269a5340f309c641e71f65fd3cf4b01049b8d9" nocase ascii wide
                        $string14_boringproxy_greyware_tool_keyword = "47532247f32b7a9f42b0dfe5a1314a674e92deef79eaab647af34507a677d375" nocase ascii wide
                        $string15_boringproxy_greyware_tool_keyword = "5805e0f064ce3aa72e5a0b4dd00c0bf4150995cb1f1b7b80f2b3a78da78d1d27" nocase ascii wide
                        $string16_boringproxy_greyware_tool_keyword = "7a778797dd640eb51defe912e8b6872df92241927193106590a2ccb92a5dc926" nocase ascii wide
                        $string17_boringproxy_greyware_tool_keyword = "828ee46c07c36e54f11e38f01898e3bd215739c28bbcf05606abe00ba0c6c51f" nocase ascii wide
                        $string18_boringproxy_greyware_tool_keyword = "89bd3a31299f6bbf9be9bcf5f1456c11333590290626f11017079fd84ee58ca1" nocase ascii wide
                        $string19_boringproxy_greyware_tool_keyword = "9a688243e33a6cddb1bb4807277e352118141e7321385024cbff655a00b7b660" nocase ascii wide
                        $string20_boringproxy_greyware_tool_keyword = "a262487a6bac019c52f1ada940aa357f0be3c69cf1232a052115e74723a65ade" nocase ascii wide
                        $string21_boringproxy_greyware_tool_keyword = "b4f3bc92ccedfbb0714c662c8d6a7842e71f1ebb2d8392ec5064b314dd5dede5" nocase ascii wide
                        $string22_boringproxy_greyware_tool_keyword = "boringproxy client -server " nocase ascii wide
                        $string23_boringproxy_greyware_tool_keyword = "boringproxy/boringproxy" nocase ascii wide
                        $string24_boringproxy_greyware_tool_keyword = /boringproxy_db\.json/ nocase ascii wide
                        $string25_boringproxy_greyware_tool_keyword = /boringproxy\-client\@default\.service/ nocase ascii wide
                        $string26_boringproxy_greyware_tool_keyword = "chown boringproxy:boringproxy "
                        $string27_boringproxy_greyware_tool_keyword = "cmd/boringproxy" nocase ascii wide
                        $string28_boringproxy_greyware_tool_keyword = "f2915f5a3885391738923ecd18faf840074c65cd2e390e1474a4d84ce315b9ff" nocase ascii wide
                        $string29_boringproxy_greyware_tool_keyword = "f5b42d933cea4d53aa975039de0cb1053287fac5ce4377d2afb663e26a5d22dd" nocase ascii wide
                        $string30_boringproxy_greyware_tool_keyword = "groupadd boringproxy" nocase ascii wide
                        $string31_boringproxy_greyware_tool_keyword = /https\:\/\/boringproxy\.io\/installation/ nocase ascii wide
                        $string32_boringproxy_greyware_tool_keyword = "pkill -u boringproxy" nocase ascii wide
                        $string33_boringproxy_greyware_tool_keyword = "runuser -l boringproxy " nocase ascii wide
                        $string34_boringproxy_greyware_tool_keyword = /setcap\scap_net_bind_service\=\+ep\sboringproxy/ nocase ascii wide
                        $string35_boringproxy_greyware_tool_keyword = "usermod -a -G boringproxy boringproxy" nocase ascii wide

    condition:
        any of them
}