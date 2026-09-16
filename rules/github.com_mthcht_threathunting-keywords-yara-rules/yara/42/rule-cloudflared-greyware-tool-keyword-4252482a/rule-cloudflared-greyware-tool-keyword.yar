rule rule_cloudflared_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cloudflared' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloudflared"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_cloudflared_greyware_tool_keyword = /\._tcp\.argotunnel\.com/ nocase ascii wide
                        $string2_cloudflared_greyware_tool_keyword = /\.v2\.argotunnel\.com/ nocase ascii wide
                        $string3_cloudflared_greyware_tool_keyword = /\/cloudflared\.git/ nocase ascii wide
                        $string4_cloudflared_greyware_tool_keyword = "/cloudflared/tunnel/"
                        $string5_cloudflared_greyware_tool_keyword = /\/cloudflared\-linux\-.{0,1000}\.deb/
                        $string6_cloudflared_greyware_tool_keyword = /\/cloudflared\-linux\-.{0,1000}\.rpm/
                        $string7_cloudflared_greyware_tool_keyword = "/usr/local/bin/cloudflared tunnel"
                        $string8_cloudflared_greyware_tool_keyword = /\\cloudflared\.exe/ nocase ascii wide
                        $string9_cloudflared_greyware_tool_keyword = /\\cloudflared\\cmd\\/ nocase ascii wide
                        $string10_cloudflared_greyware_tool_keyword = /\\cloudflared\-2023\./ nocase ascii wide
                        $string11_cloudflared_greyware_tool_keyword = /\\cloudflared\-2024\./ nocase ascii wide
                        $string12_cloudflared_greyware_tool_keyword = "07b95428cfb9cb49c2447c2ff9fbc503225d5de7ff70c643f45399fc2f08c48c" nocase ascii wide
                        $string13_cloudflared_greyware_tool_keyword = "0b917a040f43b5b120a3288f76e857203cc52f51c2f78c997d4d0c2da3d0c0c5" nocase ascii wide
                        $string14_cloudflared_greyware_tool_keyword = "0ec73349570f7d8546b9ddfd6b0b409cd622abc133be641bb2a414a2d2b9a21e" nocase ascii wide
                        $string15_cloudflared_greyware_tool_keyword = "17fa4fd9db3006f9aa649b0160770ebb9e9b8a599f6fb5afce83a16a7cb41bdd" nocase ascii wide
                        $string16_cloudflared_greyware_tool_keyword = "1b3e09c31048ec7f2ef06166eb47dcdf0e563ca07b6dcc1318fa6f7db3feb458" nocase ascii wide
                        $string17_cloudflared_greyware_tool_keyword = "2fb6c04c4f95fb8d158af94c137f90ac820716deaf88d8ebec956254e046cb29" nocase ascii wide
                        $string18_cloudflared_greyware_tool_keyword = "33c9fa0bbaca1c4af7cf7c6016cda366612f497d08edd017bced7c617baa7fc2" nocase ascii wide
                        $string19_cloudflared_greyware_tool_keyword = "33e6876bd55c2db13a931cf812feb9cb17c071ab45d3b50c588642b022693cdc" nocase ascii wide
                        $string20_cloudflared_greyware_tool_keyword = "55c11ee0078d85ed35d7df237458e40b6ad687f46fc78b1886f30c197e1683c1" nocase ascii wide
                        $string21_cloudflared_greyware_tool_keyword = "561304bd23f13aa9185257fb0f055e8790dc64e8cf95287e2bfc9fec160eecf8" nocase ascii wide
                        $string22_cloudflared_greyware_tool_keyword = "569b8925a41bd1426fc9f88a4d00aa93da747ed4a5ec1c638678ac62ae1a7114" nocase ascii wide
                        $string23_cloudflared_greyware_tool_keyword = "5868fed5581f3fb186c94b6be63f8b056c571159edb65cc5dafb84553e888d39" nocase ascii wide
                        $string24_cloudflared_greyware_tool_keyword = "62700c23ce8560628d8eb07ab2adcf863ad901c9f631bb45ed4b4f801f35b2a5" nocase ascii wide
                        $string25_cloudflared_greyware_tool_keyword = "6ee5eab9a9aa836ac397746a20afbb671971c6553bf8d6a844ba0a7a8de8447e" nocase ascii wide
                        $string26_cloudflared_greyware_tool_keyword = "9a6f666b2d691d7c6aadd7b854b26cffd76735e9622f3613577b556fe29eb6a1" nocase ascii wide
                        $string27_cloudflared_greyware_tool_keyword = "b3d21940a10fdef5e415ad70331ce257c24fe3bcf7722262302e0421791f87e8" nocase ascii wide
                        $string28_cloudflared_greyware_tool_keyword = "b7e394578b41e9a71857e59d04b7bf582e3d0d15f314ab69f269be474a4b9e1a" nocase ascii wide
                        $string29_cloudflared_greyware_tool_keyword = "ca6ac5c1c1f30675eecf91fe295d703007a754c1b320609ede7aa4783d899e9e" nocase ascii wide
                        $string30_cloudflared_greyware_tool_keyword = /\-\-chown\=nonroot\s\/go\/src\/github\.com\/cloudflare\/cloudflared\/cloudflared\s\/usr\/local\/bin\//
                        $string31_cloudflared_greyware_tool_keyword = "cloudflared tunnel --config " nocase ascii wide
                        $string32_cloudflared_greyware_tool_keyword = "cloudflared tunnel create " nocase ascii wide
                        $string33_cloudflared_greyware_tool_keyword = "cloudflared tunnel info " nocase ascii wide
                        $string34_cloudflared_greyware_tool_keyword = "cloudflared tunnel list" nocase ascii wide
                        $string35_cloudflared_greyware_tool_keyword = "cloudflared tunnel login" nocase ascii wide
                        $string36_cloudflared_greyware_tool_keyword = "cloudflared tunnel route dns " nocase ascii wide
                        $string37_cloudflared_greyware_tool_keyword = "cloudflared tunnel route ip add " nocase ascii wide
                        $string38_cloudflared_greyware_tool_keyword = "cloudflared tunnel route ip show" nocase ascii wide
                        $string39_cloudflared_greyware_tool_keyword = "cloudflared tunnel run " nocase ascii wide
                        $string40_cloudflared_greyware_tool_keyword = /cloudflared\-amd64\.pkg/ nocase ascii wide
                        $string41_cloudflared_greyware_tool_keyword = /cloudflared\-windows\-386\.exe/ nocase ascii wide
                        $string42_cloudflared_greyware_tool_keyword = /cloudflared\-windows\-amd64\.exe/ nocase ascii wide
                        $string43_cloudflared_greyware_tool_keyword = /cloudflared\-windows\-amd64\.msi/ nocase ascii wide
                        $string44_cloudflared_greyware_tool_keyword = "d6c358a2b66fae4f2c9fa4ffa8cd37f6ab9b7d27c83414f70c1d6a210812f0fa" nocase ascii wide
                        $string45_cloudflared_greyware_tool_keyword = "d79111ec8fa3659c887dd4e82f8ce6ff39391de6860ca0c2045469d6ab76a44f" nocase ascii wide
                        $string46_cloudflared_greyware_tool_keyword = "dc76f7c6b506d3ec4a92d9a0cda9678c3cb58a9096587dde15897709c7b23a33" nocase ascii wide
                        $string47_cloudflared_greyware_tool_keyword = "e8118e74c74a62a1d8dc291cb626f46d0056b1284726c2a5d671e20a5e92270c" nocase ascii wide
                        $string48_cloudflared_greyware_tool_keyword = /echo\s\'alias\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/
                        $string49_cloudflared_greyware_tool_keyword = /echo\s\'alias\sfind\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\>\>\s\\"\$user\/\.bashrc\\"/
                        $string50_cloudflared_greyware_tool_keyword = "ed4f5607dbc3fec5d43fbc22fb12a79d8bca07aa60c8733db7f495b7210d631f" nocase ascii wide
                        $string51_cloudflared_greyware_tool_keyword = "fffec1382a3f65ecb8f1ebb2c74e3d7aa57485fb4cff4014aadc10b8e9f3abc8" nocase ascii wide
                        $string52_cloudflared_greyware_tool_keyword = /protocol\-v2\.argotunnel\.com/ nocase ascii wide
                        $string53_cloudflared_greyware_tool_keyword = /sc\screate\sCloudflared\sbinPath\=\\/ nocase ascii wide
                        $string54_cloudflared_greyware_tool_keyword = /sc\.exe\screate\sCloudflared\sbinPath\=\\/ nocase ascii wide
                        $string55_cloudflared_greyware_tool_keyword = /sudo\ssystemctl\sedit\s\-\-full\scloudflared\.service/
                        $string56_cloudflared_greyware_tool_keyword = /test\-cloudflare\-tunnel\-cert\-json\.pem/ nocase ascii wide
                        $string57_cloudflared_greyware_tool_keyword = /update\.argotunnel\.com/ nocase ascii wide

    condition:
        any of them
}