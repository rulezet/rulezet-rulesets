rule rule_AD_Miner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AD_Miner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD_Miner"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AD_Miner_greyware_tool_keyword = /\/AD_Miner\.git/ nocase ascii wide
                        $string2_AD_Miner_greyware_tool_keyword = "/AD_Miner/releases/" nocase ascii wide
                        $string3_AD_Miner_greyware_tool_keyword = "006d97f8510e34966ebd1901686cf407a57663ad42374e40c023c6611595d1e3" nocase ascii wide
                        $string4_AD_Miner_greyware_tool_keyword = "03adcafddad36073108832b0c7541b0f398c074c42693a0fa847f8d7f789cd7e" nocase ascii wide
                        $string5_AD_Miner_greyware_tool_keyword = "182d8cd3ed748f2fd1e1d5195eb56e6b4c12cd27241f47ccb965cd657bcf4c07" nocase ascii wide
                        $string6_AD_Miner_greyware_tool_keyword = "1853adeeee45b385f71719b52c95f1c84c040d70296157d2ee52bd040aff39cd" nocase ascii wide
                        $string7_AD_Miner_greyware_tool_keyword = "1df2598fa2ca5e42fc9e4d4d0cf1e67ed61ab2b9ff29b9da372cee03d817ad2b" nocase ascii wide
                        $string8_AD_Miner_greyware_tool_keyword = "23d1a218ea1aa584c37006037a152e7d51ddb7e4328cba41eddf9ce40240b5de" nocase ascii wide
                        $string9_AD_Miner_greyware_tool_keyword = "29cacc6ed6f7bfe7412947ead514e4081c7a71bb22e4c959a9c233cec9e54a27" nocase ascii wide
                        $string10_AD_Miner_greyware_tool_keyword = "2e7a9e27d26187a0ee5fd4a47c785fcd5b1daaf4a076ad4e156a0827d1f6df4f" nocase ascii wide
                        $string11_AD_Miner_greyware_tool_keyword = "306a981bc54a0720a927f9c10f35db8f8c884d923d2c516f022ca6a7b0950836" nocase ascii wide
                        $string12_AD_Miner_greyware_tool_keyword = "34848aab797df134ed0268cbc77a7db060f63e0ccba71062c9e6b1512e6b6993" nocase ascii wide
                        $string13_AD_Miner_greyware_tool_keyword = "38cd3309626aa2310571aa17637b72281c54aa873a2782dcc7c5f7cdb20c8985" nocase ascii wide
                        $string14_AD_Miner_greyware_tool_keyword = "47a5be9f74f89fe03ee5f7db50e5efaf858629e992cfc78c99562bcd888753f2" nocase ascii wide
                        $string15_AD_Miner_greyware_tool_keyword = "4a144263cc2ecadea15182ecfca96ab398f5a1c8ee7b2f6ce6cb35b595ec9e9c" nocase ascii wide
                        $string16_AD_Miner_greyware_tool_keyword = "4b01df48ff3611b58680b8671c5371fed09b18333fe608187470666cb5c906ce" nocase ascii wide
                        $string17_AD_Miner_greyware_tool_keyword = "540199cba6c77f452c01d554ca2e9d5e1203896f81695182f76e703595d2ed0a" nocase ascii wide
                        $string18_AD_Miner_greyware_tool_keyword = "54093af487e6bfbe0ac27b0470a11ff5144130b3340bd5ade5c307cd9a2d2456" nocase ascii wide
                        $string19_AD_Miner_greyware_tool_keyword = "589472bbf12e3f53c7cf3447a6b280dd9931600441c8251472c01b3ff5b36c8f" nocase ascii wide
                        $string20_AD_Miner_greyware_tool_keyword = "5ea16e19f72ef48bae23711ec666f2bc8e791ff51e3abf6158afb4f5997ceb0e" nocase ascii wide
                        $string21_AD_Miner_greyware_tool_keyword = "6a5ef3f47ea5813d221d0b2742ba2dd7c05c4ad02fec93fe93ec91a030e643fc" nocase ascii wide
                        $string22_AD_Miner_greyware_tool_keyword = "6f3b17759a79f9cee899d61622d88b6a5f87aa7d8ecdc8c4d82fd0386c3e8c0a" nocase ascii wide
                        $string23_AD_Miner_greyware_tool_keyword = "73d07981ab0538707f5045dc72a89ff0c7dd2a4c403950cc77ee13c8ca6c65b4" nocase ascii wide
                        $string24_AD_Miner_greyware_tool_keyword = "7b0e1417692e9ea1fe147c7e1f63461219c66a571affd8b807d655bf145090f1" nocase ascii wide
                        $string25_AD_Miner_greyware_tool_keyword = "8c44028d1edb931e5561198ca64cfe1e078097ba236fd6ed14e553d9ff114f00" nocase ascii wide
                        $string26_AD_Miner_greyware_tool_keyword = "8d551e03684d6dad75e286f8f0c06a7d0e7e2c6a0830c2b3986301fb380639a2" nocase ascii wide
                        $string27_AD_Miner_greyware_tool_keyword = "9b4d79ab99acc97ca17ba9125218aac2374e37fdf071edd871294f2a493e68d9" nocase ascii wide
                        $string28_AD_Miner_greyware_tool_keyword = "a0005f263f682b7623cf12d1ca7d47d3c4108591019131e413a49566c7458081" nocase ascii wide
                        $string29_AD_Miner_greyware_tool_keyword = "a37163c7c31a96ed6d72fb1b9e792ca8245c2bea5504fa87178fda29f00a0e6f" nocase ascii wide
                        $string30_AD_Miner_greyware_tool_keyword = "a5fa4d3e02ec0196dd34d81d21118e6bf4014405cefd9a8e99b3fec15d4bf057" nocase ascii wide
                        $string31_AD_Miner_greyware_tool_keyword = "a8dc7da67b4c6211d0486ba8b5bed5a0fdf894109f8861acf43db8a1e87e5d74" nocase ascii wide
                        $string32_AD_Miner_greyware_tool_keyword = "a974d7a0717319394a473b04e6c227cf30158140fe2546ca9210acbaa1630518" nocase ascii wide
                        $string33_AD_Miner_greyware_tool_keyword = "aed35b08d85842b94df3b093cbb2ed6dc8d240567275b7880ddb93da9f097154" nocase ascii wide
                        $string34_AD_Miner_greyware_tool_keyword = "bb651a2795e62aee6efd88e889c2c7f553f4df16e59562182b5565d34d1e6970" nocase ascii wide
                        $string35_AD_Miner_greyware_tool_keyword = "be57fdfea2475688c89f91967e17371265f6803b3edfba4026befd6272c86e71" nocase ascii wide
                        $string36_AD_Miner_greyware_tool_keyword = "bf9c44a258f8494cd015d4211896068c38fdaec54ab1e0f84295a78482a070c8" nocase ascii wide
                        $string37_AD_Miner_greyware_tool_keyword = "c491a40347069ca5f75d4c62435fde16c4fec08656fd88f5b502825dfcbc31cf" nocase ascii wide
                        $string38_AD_Miner_greyware_tool_keyword = "c91e3e1822b0d7a6c47c27b89753d5f1cbb3bb0759422fc5729d50a1a9eef0f6" nocase ascii wide
                        $string39_AD_Miner_greyware_tool_keyword = "cfde70b05b27b08980827e7120b36d0d6c3b93a079ee5f54a8fd7a1f6e3aa18f" nocase ascii wide
                        $string40_AD_Miner_greyware_tool_keyword = "d2c77570cddbb514f155621f4999c4a6b46454b2aee4f5b48a05a89e57f087fa" nocase ascii wide
                        $string41_AD_Miner_greyware_tool_keyword = "e20a5a7af7ee08db7008f0496f29b839d101f3d913410c24ec901273865567c4" nocase ascii wide
                        $string42_AD_Miner_greyware_tool_keyword = "e76a240d76ab6e15db2077ea6742538a2cc9471b48467b7b5930831a37a1c140" nocase ascii wide
                        $string43_AD_Miner_greyware_tool_keyword = "ea03efacd106e0731b520860fd0b6babc8b9bd5300f25e53d66ac833cc867124" nocase ascii wide
                        $string44_AD_Miner_greyware_tool_keyword = "ef1dd208731a0adf0207f096af478b1be9465d375c60d229be616fd59a2a2dda" nocase ascii wide
                        $string45_AD_Miner_greyware_tool_keyword = "fcb8c6993403e3d29d3bd980eadc0e40984252d0d777236f9d80f4d1e9de9d35" nocase ascii wide
                        $string46_AD_Miner_greyware_tool_keyword = "ff94ad03ba7f695b06de1179867e2883d9fab083620e55cbe647b79c093492cb" nocase ascii wide
                        $string47_AD_Miner_greyware_tool_keyword = "Mazars-Tech/AD_Miner" nocase ascii wide

    condition:
        any of them
}