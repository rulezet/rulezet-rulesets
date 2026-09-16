rule rule_fscan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_fscan_offensive_tool_keyword = /\sfscan\.exe/ nocase ascii wide
                        $string2_fscan_offensive_tool_keyword = /\sfscan32\.exe/ nocase ascii wide
                        $string3_fscan_offensive_tool_keyword = /\sfscan64\.exe/ nocase ascii wide
                        $string4_fscan_offensive_tool_keyword = /\sfscanarm64\.exe/ nocase ascii wide
                        $string5_fscan_offensive_tool_keyword = /\sfscanarmv6\.exe/ nocase ascii wide
                        $string6_fscan_offensive_tool_keyword = /\sfscanarmv7\.exe/ nocase ascii wide
                        $string7_fscan_offensive_tool_keyword = /\.\/fscan/
                        $string8_fscan_offensive_tool_keyword = /\/fscan\.exe/ nocase ascii wide
                        $string9_fscan_offensive_tool_keyword = /\/fscan\.git/ nocase ascii wide
                        $string10_fscan_offensive_tool_keyword = "/fscan/releases/download/" nocase ascii wide
                        $string11_fscan_offensive_tool_keyword = "/fscan_freebsd_arm64"
                        $string12_fscan_offensive_tool_keyword = "/fscan_mac_arm64"
                        $string13_fscan_offensive_tool_keyword = "/fscan32 "
                        $string14_fscan_offensive_tool_keyword = /\/fscan32\.exe/ nocase ascii wide
                        $string15_fscan_offensive_tool_keyword = "/fscan386 "
                        $string16_fscan_offensive_tool_keyword = /\/fscan64\.exe/ nocase ascii wide
                        $string17_fscan_offensive_tool_keyword = "/fscanamd64 "
                        $string18_fscan_offensive_tool_keyword = /\/fscanarm64\.exe/ nocase ascii wide
                        $string19_fscan_offensive_tool_keyword = /\/fscanarmv6\.exe/ nocase ascii wide
                        $string20_fscan_offensive_tool_keyword = /\/fscanarmv7\.exe/ nocase ascii wide
                        $string21_fscan_offensive_tool_keyword = /\[\+\]\sPocScan\s/ nocase ascii wide
                        $string22_fscan_offensive_tool_keyword = /\[\+\]\sWmiExec\s/ nocase ascii wide
                        $string23_fscan_offensive_tool_keyword = /\\fscan\.exe/ nocase ascii wide
                        $string24_fscan_offensive_tool_keyword = /\\fscan\\common\\proxy/ nocase ascii wide
                        $string25_fscan_offensive_tool_keyword = /\\fscan\\WebScan\\pocs\\/ nocase ascii wide
                        $string26_fscan_offensive_tool_keyword = /\\fscan32\.exe/ nocase ascii wide
                        $string27_fscan_offensive_tool_keyword = /\\fscan64\.exe/ nocase ascii wide
                        $string28_fscan_offensive_tool_keyword = /\\fscanarm64\.exe/ nocase ascii wide
                        $string29_fscan_offensive_tool_keyword = /\\fscanarmv6\.exe/ nocase ascii wide
                        $string30_fscan_offensive_tool_keyword = /\\fscanarmv7\.exe/ nocase ascii wide
                        $string31_fscan_offensive_tool_keyword = "027bf95a524ee9daf472869e548c9221b16d4a5230de187e5ae9ba9a9e98cfba" nocase ascii wide
                        $string32_fscan_offensive_tool_keyword = "06e7d0050e4aac352307c5b20372badd841e275bafc1dfe2ecbd0f2ad6366f81" nocase ascii wide
                        $string33_fscan_offensive_tool_keyword = "0b3924b330e85ff7db62e4d7e665397fd04c3b056b135a184aa87fcabbf1fad9" nocase ascii wide
                        $string34_fscan_offensive_tool_keyword = "0b8e4ffbabf5f6e7167013a324e67e2a359d35043145eb8af7d8815e7e12242b" nocase ascii wide
                        $string35_fscan_offensive_tool_keyword = "16bef09e16119f1754a6b4283e93ff7a17cfdd7c043c3ff05a3d41f128ead52e" nocase ascii wide
                        $string36_fscan_offensive_tool_keyword = "1a524806875110320dacb05bb8a00bbe07f8618ff23a82effad887df9952f459" nocase ascii wide
                        $string37_fscan_offensive_tool_keyword = "25125be2945ae98284abb64b279fe13021d1d02895b85a4e02a4fcd6ec8415cc" nocase ascii wide
                        $string38_fscan_offensive_tool_keyword = "3b66b9ef669a7aca55f87ccce04ab1849d23d18c522b5f2514ca0637398ca250" nocase ascii wide
                        $string39_fscan_offensive_tool_keyword = "3f63c1d262a6e900833b2dbd615f72006785c124d4ca7fda01cd621ca615865f" nocase ascii wide
                        $string40_fscan_offensive_tool_keyword = "405e9c6f0b2ea355c45a80236dd541ecee957c73194dc3e7948b3ae02c8c70ea" nocase ascii wide
                        $string41_fscan_offensive_tool_keyword = "5cd6f1ac11ce75c742358c9225983712e9ae31fd16e052b377a795d8ba4d18f6" nocase ascii wide
                        $string42_fscan_offensive_tool_keyword = "62ba281147ceeefca5bd15f58ac52125bc42b0e134a6fcb4bd90efdae0fce318" nocase ascii wide
                        $string43_fscan_offensive_tool_keyword = "633bd0cfd64ccc0030ca38148459f71dba02cf3ce103ce24d8a0872c00a26eeb" nocase ascii wide
                        $string44_fscan_offensive_tool_keyword = "675f1d8076801a64dc3c39916e52ac7b345b7d1c9454a01f270ca9796dd86f7e" nocase ascii wide
                        $string45_fscan_offensive_tool_keyword = "69e041111e26111f406a95d9b91b5004f60ba367a0c90ffe34146e064513e56b" nocase ascii wide
                        $string46_fscan_offensive_tool_keyword = "6facdc6a09f2d89e156a7b11dc628815f4a00ba25ce37f9443f4fb7f50877f85" nocase ascii wide
                        $string47_fscan_offensive_tool_keyword = "723c4fa580d252cfdafda962e5abb6b45eec8c9aae56497d98983ce6dcf9a1ac" nocase ascii wide
                        $string48_fscan_offensive_tool_keyword = "78eed41cec221edd4ffed223f2fd2271a96224fd1173ed685c8c0b274fe93029" nocase ascii wide
                        $string49_fscan_offensive_tool_keyword = "7beae9c75c8e6e87a776f82461256a983e0fcd2ab169ea2293efa08f486ed33b" nocase ascii wide
                        $string50_fscan_offensive_tool_keyword = "7e6b9406c2a12c93a7c56e4e2c79dd4eb1e562c772aef13ebd006abb727a2854" nocase ascii wide
                        $string51_fscan_offensive_tool_keyword = "84dbd3a0c2e858b59822ee50b7d72972851ca692416c15c5f351831381aa4db9" nocase ascii wide
                        $string52_fscan_offensive_tool_keyword = "929dbe39814a7b4acba0efe0a552840aeb1e9a5b1f8045be633e6fb68f4e2155" nocase ascii wide
                        $string53_fscan_offensive_tool_keyword = "9b140ac9343598961b3d5699eedc389d78c7c88271453fa37c7e3d2853364234" nocase ascii wide
                        $string54_fscan_offensive_tool_keyword = "9f9675403c2be03232b1c3abe344bf0f4188454955ba89592be52ef77add4a39" nocase ascii wide
                        $string55_fscan_offensive_tool_keyword = "9fc3fe230f30e5b9f9bb15065bf62269f494f51f744857d6b8ac90a9937f5bc0" nocase ascii wide
                        $string56_fscan_offensive_tool_keyword = "a25c5e7baec3573c2a78872808c709d702714f3a11e57d06b62244c3eca2a834" nocase ascii wide
                        $string57_fscan_offensive_tool_keyword = "aa12c40bc0ef87b1b706f1e9062d72d8c67c3b4b3347741efb38cf71817777d2" nocase ascii wide
                        $string58_fscan_offensive_tool_keyword = "b19a46f99b649dc731ed5c8410bda7e0385d15e1b9aab1e467b05dccd7753865" nocase ascii wide
                        $string59_fscan_offensive_tool_keyword = "b26458a0b60f4af597433fb7eff7b949ca96e59330f4e4bb85005e8bbcfa4f59" nocase ascii wide
                        $string60_fscan_offensive_tool_keyword = "b4a1ab9bd2528e57f4a018ac84934c6bdcd67aaaf269f76c15fa739432409f3b" nocase ascii wide
                        $string61_fscan_offensive_tool_keyword = "b9919cdb3ebf7abed7458e357a71924bb0dd43332e90c30a6f146caefcf56baa" nocase ascii wide
                        $string62_fscan_offensive_tool_keyword = "bc422a4e1b6a351ac6fe73d496015cfa6a9dbd5e38566c6f44a59faff83ee95a" nocase ascii wide
                        $string63_fscan_offensive_tool_keyword = "c7985c82769ce2d6d68e3ed3926df1bc47523990c56cfa1ebe3e511e4b96a903" nocase ascii wide
                        $string64_fscan_offensive_tool_keyword = "c86b6630f868d20303e940cd8f1a8805f1013bc567938a79cedb318b07f5f498" nocase ascii wide
                        $string65_fscan_offensive_tool_keyword = "d61ec93dd0760f68a6b98f8dd073fcbbe7edeb55cbd3281f12df0af42ce6f794" nocase ascii wide
                        $string66_fscan_offensive_tool_keyword = "d9940f5a09a04a949545eedb6818ce0ce001cc7596a63959e0940d31b6dc4834" nocase ascii wide
                        $string67_fscan_offensive_tool_keyword = "d9d5daaecd31c7616b01456da34cb3b51006b5a7697af4cadfa8167e7a8b6f81" nocase ascii wide
                        $string68_fscan_offensive_tool_keyword = "dc5d95d4ce6cee631b546e1bbfa9f090f66e4167edd5dd828f567c7fc30978dc" nocase ascii wide
                        $string69_fscan_offensive_tool_keyword = "e2940f2785f9f9b38e5cac80100a401145f558602a7af45475760884aeba44f9" nocase ascii wide
                        $string70_fscan_offensive_tool_keyword = "ebaa36db295f1c3a7d59e460ce6813221d0097f3c12ce26e818d4d4ac83c0919" nocase ascii wide
                        $string71_fscan_offensive_tool_keyword = "f34bd1d485de437fe18360d1e850c3fd64415e49d691e610711d8d232071a0b1" nocase ascii wide
                        $string72_fscan_offensive_tool_keyword = "f4ea99dc41cb7922d01955eef9303ec3a24b88c3318138855346de1e830ed09e" nocase ascii wide
                        $string73_fscan_offensive_tool_keyword = "f6bb09ea48d85445fb1295a7b93ead6700a17c8f839624871f4faf024e18e39f" nocase ascii wide
                        $string74_fscan_offensive_tool_keyword = /fscan\s\-h\s.{0,1000}\// nocase ascii wide
                        $string75_fscan_offensive_tool_keyword = /fscan\.exe\s\-/ nocase ascii wide
                        $string76_fscan_offensive_tool_keyword = /Plugins\.Brutelist/
                        $string77_fscan_offensive_tool_keyword = "Running final exploit packet" nocase ascii wide
                        $string78_fscan_offensive_tool_keyword = "shadow1ng/fscan" nocase ascii wide
                        $string79_fscan_offensive_tool_keyword = /User\-Agent\:\s.{0,1000}echo\;\secho\;\s\/bin\/bash\s\-c\s/

    condition:
        any of them
}