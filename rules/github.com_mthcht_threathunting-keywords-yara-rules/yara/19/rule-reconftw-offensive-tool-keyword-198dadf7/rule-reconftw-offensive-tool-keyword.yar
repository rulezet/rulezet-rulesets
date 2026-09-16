rule rule_reconftw_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reconftw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reconftw"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_reconftw_offensive_tool_keyword = " -mc all -fc 404 -sf -noninteractive -of json"
                        $string2_reconftw_offensive_tool_keyword = /\s\-\-private\-key\sterraform\-keys\sreconFTW\.yml/
                        $string3_reconftw_offensive_tool_keyword = " reconFTW installer/updater script "
                        $string4_reconftw_offensive_tool_keyword = /\sreconftw\.sh\s/
                        $string5_reconftw_offensive_tool_keyword = " --top-ports 200 -sV -n -Pn --open --max-retries 2 --script vulners"
                        $string6_reconftw_offensive_tool_keyword = /\/fuzz_wordlist\.txt/
                        $string7_reconftw_offensive_tool_keyword = /\/n0kovo_subdomains_huge\.txt/
                        $string8_reconftw_offensive_tool_keyword = /\/reconftw\.cfg/
                        $string9_reconftw_offensive_tool_keyword = /\/reconftw\.git/
                        $string10_reconftw_offensive_tool_keyword = /\/reconftw\.sh/
                        $string11_reconftw_offensive_tool_keyword = /\/reconFTW\.yml/
                        $string12_reconftw_offensive_tool_keyword = "/reconftw/Recon/"
                        $string13_reconftw_offensive_tool_keyword = "/reconftw:main"
                        $string14_reconftw_offensive_tool_keyword = "/reconftw-data"
                        $string15_reconftw_offensive_tool_keyword = /\/subdomains_n0kovo_big\.txt/
                        $string16_reconftw_offensive_tool_keyword = /\/sudoers\.d\/reconFTW/
                        $string17_reconftw_offensive_tool_keyword = "006ace1aaf8ef3027f96f25e3408b9a95c11bc2009288e570de2c013daaaea32"
                        $string18_reconftw_offensive_tool_keyword = "03a2655c68c8fba7b1351d8ac272f7d14df5c19ef2aa5ea66515991595babdbc"
                        $string19_reconftw_offensive_tool_keyword = "054f6b13f3cf2ca61c08262584bca599685344bf74979f7806da6351d5a1e4ec"
                        $string20_reconftw_offensive_tool_keyword = "057be14a7e848f100a489cc66a10416ffa70af9752745f95fa56c6df73c35d27"
                        $string21_reconftw_offensive_tool_keyword = "07767d1f2d939b8c1fcd6c4d2052069d711719f4e238c800fd500fac405df316"
                        $string22_reconftw_offensive_tool_keyword = "0953f449b99d30bbf1f38beb8e820b996c29ab9b756867bf54819a58b020c05b"
                        $string23_reconftw_offensive_tool_keyword = "0c9720ca9be018a435d41614f7cf66cf4aefda0c89c0fc829265315a2b0cc595"
                        $string24_reconftw_offensive_tool_keyword = "0db3092377cd7af2f253b637374742921b7db93b6d395ede84a826a14d2ad7cb"
                        $string25_reconftw_offensive_tool_keyword = "0df149772508a04604ef6e5a1bd46715b95c81bd327e0ab9ca912d82a0bc82b4"
                        $string26_reconftw_offensive_tool_keyword = "13dad918ff8a6a45552b0df38e2cb573cc3be2ce7fad3ae59d35b32be1ed6f9b"
                        $string27_reconftw_offensive_tool_keyword = "1617cf34f5dd98fd31a4c49f522bff51e951a21db40a46f3e7b750f9b600c4e5"
                        $string28_reconftw_offensive_tool_keyword = "23a1cde43eee4ebc3c7082d5827672fbf974b25a4cdf368538e4b0af26fda677"
                        $string29_reconftw_offensive_tool_keyword = "2b9f65496220a60c706897a88ed0417cdd57d1fe8c7af22abf2a69e718a0e1fc"
                        $string30_reconftw_offensive_tool_keyword = "36855e25edfdc11367442a67a436dbb0cc79454dbf92435de3e6017f25378703"
                        $string31_reconftw_offensive_tool_keyword = "36a5fc4f46aea01f852923cd75f58793d9aa05abd8567ee8e0ab97c9270b6d1a"
                        $string32_reconftw_offensive_tool_keyword = "3bb82ba795352c150f16bb53c7c457583dcfe44227e693402aa88b80289c0197"
                        $string33_reconftw_offensive_tool_keyword = "3dac2fe1a99790885eecaee1f0f72d8e06b256b08593aab8945229b5f59efc16"
                        $string34_reconftw_offensive_tool_keyword = "402ea71c95ba45c95e58a17cf0903b78ddc4238afb79df1d9ab188d203b77d43"
                        $string35_reconftw_offensive_tool_keyword = "419d762e596871ecea36882eef2d5f2fc99804c069bb8e1852636844faf0a52a"
                        $string36_reconftw_offensive_tool_keyword = "478b63e32ecfb5302ba2e6da13a8c16055ad0885c3f65b90f52e6c23240a35a1"
                        $string37_reconftw_offensive_tool_keyword = "47adbdef1e6009d49324930f31963210ebaf0f9a3e8cb293f027d81c1aedc309"
                        $string38_reconftw_offensive_tool_keyword = "4cf4468e6bc420ffeb92c8ebad8009cc23f2b5fb35b789511d4cc73d7ed157d7"
                        $string39_reconftw_offensive_tool_keyword = "54398cb2ba983d091f03ee04da0fd726b0f093d561808d336cf6087bd42f1f16"
                        $string40_reconftw_offensive_tool_keyword = "54b65d41295622a4039388c986b9df46b81960d797db9b436179c6b3d1a6b82f"
                        $string41_reconftw_offensive_tool_keyword = "58d80168520f8d397087fea5495f9955f7a1399131f5b963d168950ec2f2a446"
                        $string42_reconftw_offensive_tool_keyword = "5fb9e4e174759ac8d6d8fb6ac151bbe0d7564759d508c246c8c9b5eb4b28c8d7"
                        $string43_reconftw_offensive_tool_keyword = "600a76fba6033e9f4a42fb3154c2f0fdc7decfc3794cb37efc2f4847739b4a4a"
                        $string44_reconftw_offensive_tool_keyword = "61796395b041af4d4a777fa249e255fed98462c18287b1c712b8c3ed33081d24"
                        $string45_reconftw_offensive_tool_keyword = "6feb42af348a1747fcefa53485fa6e6254ee5ad52b7d96d9027591efee282ee5"
                        $string46_reconftw_offensive_tool_keyword = "733238cfadd968469af3b91b6aa772958604f9bb1f3808ee7f5cb9870ddabdcb"
                        $string47_reconftw_offensive_tool_keyword = "7460daaecb43751385fc4ec001ac2496d9d8041ccafbef3793262644f500baf6"
                        $string48_reconftw_offensive_tool_keyword = "7cac4f61fe27bdb744f64ae81d3ff0611a42bb814ae589dacedb0d29c7ccdb93"
                        $string49_reconftw_offensive_tool_keyword = "7d675410e845e1f645226deca1725ff724df5a61d3235b3e3af3d0b1d4090cf8"
                        $string50_reconftw_offensive_tool_keyword = "8299345196309b9e228c921f059aafbfdb9f0420253215aaf531309b1aded71d"
                        $string51_reconftw_offensive_tool_keyword = "89bfa445e98341969422b43a84c9751b15eb7db2b10e2be755629d04b4cd2a31"
                        $string52_reconftw_offensive_tool_keyword = "8bf86bce665800caee44d5491c9bc54e9eb86d2efe6c665343f1cb679e2a6690"
                        $string53_reconftw_offensive_tool_keyword = "8ecf8d9dc253ab974d080663d0b238fb4e5c178b878fbc6850241bf72ea3dd8b"
                        $string54_reconftw_offensive_tool_keyword = "95ea0b9f5014787d2743ece13f2800e15e4e24a4c3b2c57576a8cdf49db88c0c"
                        $string55_reconftw_offensive_tool_keyword = "9eb720213fd4b7e283384dd03306b7a4a632234ff743f9812169d0e22efb24ed"
                        $string56_reconftw_offensive_tool_keyword = "aa09c80172ca9e37f28d8da004771b57c2ba1eac4a8957b7b0422c0fcbd6f59d"
                        $string57_reconftw_offensive_tool_keyword = "ab8ef44ac5829b0b14890ad48e4f015725748a0910f1d15aa0fdd5ed911ff7cf"
                        $string58_reconftw_offensive_tool_keyword = "ae350439aa4332fe5d7ed69a210d1ec0362ea147b9326d49730e18054e7e7c03"
                        $string59_reconftw_offensive_tool_keyword = "afda444341d9478be17dbb1e4fcee7b7944920e26b83a18978be10d8ecfedf76"
                        $string60_reconftw_offensive_tool_keyword = "b15de7b31497b070c3dcca0797cf38a75d828ef8ea76762d315ec876dec2e2c4"
                        $string61_reconftw_offensive_tool_keyword = "b3240430623b16bab37181f538e1f2ad9c1dacd9e55f1dad013b9e2269d3cc93"
                        $string62_reconftw_offensive_tool_keyword = "b5bc556355336910d01dadab5af53e9726b1722a247bc6124ee4a3e4431ec8de"
                        $string63_reconftw_offensive_tool_keyword = "b704713e230f60048904dcdcd8d61c7ef8f2750a60d52f57b914c44f1bae5054"
                        $string64_reconftw_offensive_tool_keyword = "ba97f0a315cf16438bb5318e47ddad24ec2bc6c851881b8ac5e3c27258d4b484"
                        $string65_reconftw_offensive_tool_keyword = "c0376b905f31c5d3440c2048498106aca7c86006fa9876ca85945d3a037705f5"
                        $string66_reconftw_offensive_tool_keyword = "c1f26f34840d12e1daeb6ee4362ae1582b564e0c1b6c6762f943dc521c694b69"
                        $string67_reconftw_offensive_tool_keyword = "c23628bad8bfff013fe5d96f50013c838c5900962550a86521e3063879a1bf9e"
                        $string68_reconftw_offensive_tool_keyword = "c7bac4df389bcfe3073fefde8fea9fc0d1057fbda2a329ad29a1566f9ded6d8d"
                        $string69_reconftw_offensive_tool_keyword = "cb5f87dbd2f764382e033f11807f823c72532878966ad60b479e523a3aef30cd"
                        $string70_reconftw_offensive_tool_keyword = "ccb0b3f1ac000921117e6695c3eb5892c70b7867a9efd00438295e3dcdbd2991"
                        $string71_reconftw_offensive_tool_keyword = "cfe2a0ee87618dc322a1f96521df4e51a5a81ba1d7e713e73ce8d3d0e9b712d0"
                        $string72_reconftw_offensive_tool_keyword = "d5166ef63bf4d35ede9f2b3649e92406f045bbbf317104f47f9a134f70ecd536"
                        $string73_reconftw_offensive_tool_keyword = "d85ebff4e801e52ef86698933ccc7d66adc5e1aae2b0a8433be591fa31046436"
                        $string74_reconftw_offensive_tool_keyword = "da6b27ef40704e6be3aed8b68a5d06482335e34e0a19bf34b900554e1d874726"
                        $string75_reconftw_offensive_tool_keyword = "e279a6912143a62d5f1a036f60a97e3c8db8609bbaf4aa56d5a85c9adf3571ca"
                        $string76_reconftw_offensive_tool_keyword = "e71047adb4f65d8d038262c8a288feb4061ec2b2dc30a4a6d168f7c0ae8c3e23"
                        $string77_reconftw_offensive_tool_keyword = "ea240f25e5b63c24148a4f4e4393fdb4a00a3a6c6e3038e395b533663762415f"
                        $string78_reconftw_offensive_tool_keyword = "ed1041a720c35f70b8354bfda4e020525553da2ae1c83dd166388c9c66522a8d"
                        $string79_reconftw_offensive_tool_keyword = "f22c8a9bf9bba73a4b5ad20ba6666c8da8b1d77eaf670448b25792336de7f512"
                        $string80_reconftw_offensive_tool_keyword = "ff50ca9ef07a4989f30156b09342e2a376fb5f852799cb54d1b311645f573cc8"
                        $string81_reconftw_offensive_tool_keyword = "kali-rolling main contrib non-free"
                        $string82_reconftw_offensive_tool_keyword = "six2dez/reconftw"
                        $string83_reconftw_offensive_tool_keyword = /target_reconftw_ipcidr\.txt/

    condition:
        any of them
}