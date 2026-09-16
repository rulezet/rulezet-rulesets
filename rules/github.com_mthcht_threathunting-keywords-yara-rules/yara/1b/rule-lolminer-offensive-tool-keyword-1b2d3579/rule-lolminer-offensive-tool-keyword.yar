rule rule_lolminer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lolminer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lolminer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lolminer_offensive_tool_keyword = /\.2miners\.com/ nocase ascii wide
                        $string2_lolminer_offensive_tool_keyword = /\.herominers\.com/ nocase ascii wide
                        $string3_lolminer_offensive_tool_keyword = /\/lolminer\.exe/ nocase ascii wide
                        $string4_lolminer_offensive_tool_keyword = /\/lolMiner_v.{0,1000}_Win64\.zip/ nocase ascii wide
                        $string5_lolminer_offensive_tool_keyword = /\/lolMinerGUI\.exe/ nocase ascii wide
                        $string6_lolminer_offensive_tool_keyword = /\\dual_mine_etc_aleph_herominer\.bat/ nocase ascii wide
                        $string7_lolminer_offensive_tool_keyword = /\\dual_mine_etc_aleph_lhr_admin\.bat/ nocase ascii wide
                        $string8_lolminer_offensive_tool_keyword = /\\dual_mine_etc_aleph_woolypooly\.bat/ nocase ascii wide
                        $string9_lolminer_offensive_tool_keyword = /\\dual_mine_ethw_aleph_herominer\.bat/ nocase ascii wide
                        $string10_lolminer_offensive_tool_keyword = /\\dual_mine_ethw_aleph_lhr_admin\.bat/ nocase ascii wide
                        $string11_lolminer_offensive_tool_keyword = /\\dual_mine_ethw_aleph_woolypooly\.bat/ nocase ascii wide
                        $string12_lolminer_offensive_tool_keyword = /\\dual_mine_rth_aleph\.bat/ nocase ascii wide
                        $string13_lolminer_offensive_tool_keyword = /\\dual_mine_rth_kls\.bat/ nocase ascii wide
                        $string14_lolminer_offensive_tool_keyword = /\\dual_mine_rth_rxd\.bat/ nocase ascii wide
                        $string15_lolminer_offensive_tool_keyword = /\\lolMiner\.cfg/ nocase ascii wide
                        $string16_lolminer_offensive_tool_keyword = /\\lolminer\.exe/ nocase ascii wide
                        $string17_lolminer_offensive_tool_keyword = /\\lolMinerGUI\.cpp/ nocase ascii wide
                        $string18_lolminer_offensive_tool_keyword = /\\lolMinerGUI\.pdb/ nocase ascii wide
                        $string19_lolminer_offensive_tool_keyword = /\\mine_aleph\.bat/ nocase ascii wide
                        $string20_lolminer_offensive_tool_keyword = /\\mine_beam\.bat/ nocase ascii wide
                        $string21_lolminer_offensive_tool_keyword = /\\mine_bittube\.bat/ nocase ascii wide
                        $string22_lolminer_offensive_tool_keyword = /\\mine_btg\.bat/ nocase ascii wide
                        $string23_lolminer_offensive_tool_keyword = /\\mine_cortex\.bat/ nocase ascii wide
                        $string24_lolminer_offensive_tool_keyword = /\\mine_ergo\.bat/ nocase ascii wide
                        $string25_lolminer_offensive_tool_keyword = /\\mine_etc\.bat/ nocase ascii wide
                        $string26_lolminer_offensive_tool_keyword = /\\mine_eth\.bat/ nocase ascii wide
                        $string27_lolminer_offensive_tool_keyword = /\\mine_eth_lhr_admin\.bat/ nocase ascii wide
                        $string28_lolminer_offensive_tool_keyword = /\\mine_ethw\.bat/ nocase ascii wide
                        $string29_lolminer_offensive_tool_keyword = /\\mine_ethw_lhr_admin\.bat/ nocase ascii wide
                        $string30_lolminer_offensive_tool_keyword = /\\mine_flux\.bat/ nocase ascii wide
                        $string31_lolminer_offensive_tool_keyword = /\\mine_flux_admin\.bat/ nocase ascii wide
                        $string32_lolminer_offensive_tool_keyword = /\\mine_gram\.bat/ nocase ascii wide
                        $string33_lolminer_offensive_tool_keyword = /\\mine_grin_32\.bat/ nocase ascii wide
                        $string34_lolminer_offensive_tool_keyword = /\\mine_ironfish\.bat/ nocase ascii wide
                        $string35_lolminer_offensive_tool_keyword = /\\mine_ironfish_gram\.bat/ nocase ascii wide
                        $string36_lolminer_offensive_tool_keyword = /\\mine_karlsen\.bat/ nocase ascii wide
                        $string37_lolminer_offensive_tool_keyword = /\\mine_nexa\.bat/ nocase ascii wide
                        $string38_lolminer_offensive_tool_keyword = /\\mine_nexa_with_oc\.bat/ nocase ascii wide
                        $string39_lolminer_offensive_tool_keyword = /\\mine_pyrin\.bat/ nocase ascii wide
                        $string40_lolminer_offensive_tool_keyword = /\\mine_radiant\.bat/ nocase ascii wide
                        $string41_lolminer_offensive_tool_keyword = /\\mine_rth\.bat/ nocase ascii wide
                        $string42_lolminer_offensive_tool_keyword = /\\mine_ubq\.bat/ nocase ascii wide
                        $string43_lolminer_offensive_tool_keyword = /\\mine_zcl\.bat/ nocase ascii wide
                        $string44_lolminer_offensive_tool_keyword = /\\triple_mine_zil_etc_aleph\.bat/ nocase ascii wide
                        $string45_lolminer_offensive_tool_keyword = /\\triple_mine_zil_ethw_aleph\.bat/ nocase ascii wide
                        $string46_lolminer_offensive_tool_keyword = "00f30b9daeee37dd8ae0c6e0f61b14b3de19d45f504ba5d288f2a45dfe3cc652" nocase ascii wide
                        $string47_lolminer_offensive_tool_keyword = "070f9bbe7bf3f68bca8bcc2b0baa1a6eadc0105e2e1766b06a0f5a912d12fcab" nocase ascii wide
                        $string48_lolminer_offensive_tool_keyword = "0f8b3d08754df255a2d275a9b27c2f324e86f73cf7c679c577b1551b6dad590e" nocase ascii wide
                        $string49_lolminer_offensive_tool_keyword = "115ac6d10a371a9f22cdf0190e84a5a4c4d5b4b625bf8d571d68f95b507424e5" nocase ascii wide
                        $string50_lolminer_offensive_tool_keyword = "263a97ae0cf8daefca89d894014060176d030af5b2e94cea2846af2e4c64c644" nocase ascii wide
                        $string51_lolminer_offensive_tool_keyword = "4059185741fed75ca2f3551cbcc522265ed3c63f15da6b12301a21668ff7c33d" nocase ascii wide
                        $string52_lolminer_offensive_tool_keyword = "43195f385c68a53280d094289acfe2730ed0c503053e704a33a563e0aa0825fe" nocase ascii wide
                        $string53_lolminer_offensive_tool_keyword = "447ea37d555fb32ea2957369ea1aeee31898a4e1f1783eb834dc9df2f469252e" nocase ascii wide
                        $string54_lolminer_offensive_tool_keyword = "451d10d93c241b86d688cba1b05c7b5ee74995b5b558e11a6a4b114d080f5dce" nocase ascii wide
                        $string55_lolminer_offensive_tool_keyword = "4a96ba27c260b02607556b05e93f631af307a6046a79936e8e229ecd84f12b7f" nocase ascii wide
                        $string56_lolminer_offensive_tool_keyword = "547b97d9bb9bfc6250599e19357911ab5ae3dde3ca5f0d49bea0e66e46799dfc" nocase ascii wide
                        $string57_lolminer_offensive_tool_keyword = "56888116d58c75328e0b32af2b26f98c1f79e6b513e436db51aa650efa55a60b" nocase ascii wide
                        $string58_lolminer_offensive_tool_keyword = "5e072a48d093df02065faaeee6bbc019e1e6c4ac85ae0b00726c5dc216886bb1" nocase ascii wide
                        $string59_lolminer_offensive_tool_keyword = "641867dbb57f198f42dc86ea0d27eaaab36190417ffc24e6a186c831a98c0051" nocase ascii wide
                        $string60_lolminer_offensive_tool_keyword = "6824586e095fec0e58ee872ecf5108b370bd8713987988510aacf3793cbe1114" nocase ascii wide
                        $string61_lolminer_offensive_tool_keyword = "73a1461ab0925ac9df52dca7f7b3b2c8e46f25e440228c17d2c95c430bf22e68" nocase ascii wide
                        $string62_lolminer_offensive_tool_keyword = "740879d5c5c757899862884c89b2d1386ff5b85a68d8d847201080f74201ed36" nocase ascii wide
                        $string63_lolminer_offensive_tool_keyword = "7419174a31b2ec7503765d473943459f5d3d959c0c69fa23da6f6f551e6464ce" nocase ascii wide
                        $string64_lolminer_offensive_tool_keyword = "7fa4e734f5dddd6e3e912dda25a744ffa615735a9e65ac1319412cd4fb91d1cc" nocase ascii wide
                        $string65_lolminer_offensive_tool_keyword = "8a01a909a9fbaeb9d1061774811d0d2b165ff7dd199fea5543a75773bd5b13a7" nocase ascii wide
                        $string66_lolminer_offensive_tool_keyword = "9680bea8301be835e4f7e35220c4dfbb48ecf51b3fb9d0405c7fa8e8abfab28e" nocase ascii wide
                        $string67_lolminer_offensive_tool_keyword = "96aaf948fb2eef6f40f56164125e6dcd819e09c444f569c1a2a7df1ec0b009d7" nocase ascii wide
                        $string68_lolminer_offensive_tool_keyword = "a0767e6ca9109d8a0e82ac8abe1a1971e03de8d734905a09854244e9d316f73a" nocase ascii wide
                        $string69_lolminer_offensive_tool_keyword = "a5e057e11af84fb4e663c3d1f580dc6df73c2cca29bb63008717590f0d53883f" nocase ascii wide
                        $string70_lolminer_offensive_tool_keyword = "aa0daaab2228d5befff8982d5b44267a0272e971799dd77225449e005ec5d83e" nocase ascii wide
                        $string71_lolminer_offensive_tool_keyword = "aeec0f065823849ebb2ded6654d59526ee8b73520117bd033a19e011c9455248" nocase ascii wide
                        $string72_lolminer_offensive_tool_keyword = "bc0ff8a55724a6ac40a71ca1b0072e40c34e80c13c26688860fdf3c4e5309f25" nocase ascii wide
                        $string73_lolminer_offensive_tool_keyword = "beb128325351c7c87a1928ec9cb98e595f39b3da1a105bf229b04548644a3957" nocase ascii wide
                        $string74_lolminer_offensive_tool_keyword = "bef1d97b5fa30aea0ddffcc7275d34f13c54bf8b812326a37e958a314968d3af" nocase ascii wide
                        $string75_lolminer_offensive_tool_keyword = "ca39b6544676022075793b762288a2d13bd3db50d4ce983c624931639dbb75c6" nocase ascii wide
                        $string76_lolminer_offensive_tool_keyword = "df117b05c21cd8ef0c6c4d85290d81532838e4645677bdb2955a968eba9da682" nocase ascii wide
                        $string77_lolminer_offensive_tool_keyword = "df3adfbca15691d22d9dd17b3247e1ef434b0b85863ce1e6900565cdbf8b1cd4" nocase ascii wide
                        $string78_lolminer_offensive_tool_keyword = "e1a58a89aa3d31654d9496700ebbfb27e2914cce90d78425864b948097c35090" nocase ascii wide
                        $string79_lolminer_offensive_tool_keyword = "e5d6d5fe4ebbae6ba141cf25faa3f05e915916b0980b90297a8b2e59b2312bb8" nocase ascii wide
                        $string80_lolminer_offensive_tool_keyword = "e7b3627d04efe0c3b201656b9bda35df126551dfb3eb47b506e1238bcc4b2ffe" nocase ascii wide
                        $string81_lolminer_offensive_tool_keyword = "eb93d18ebddbcc79c037708558cbf1295b85a75230ba1690f07d287433d48fd1" nocase ascii wide
                        $string82_lolminer_offensive_tool_keyword = "ef3eb0e2dc2a3be441eef0bdc97eb16eb311187a6387f3e757eb0569795dcc41" nocase ascii wide
                        $string83_lolminer_offensive_tool_keyword = /eu1\-etc\.ethermine\.org/ nocase ascii wide
                        $string84_lolminer_offensive_tool_keyword = /europe\.equihash\-hub\.miningpoolhub\.com/ nocase ascii wide
                        $string85_lolminer_offensive_tool_keyword = "f67880e200d99b83404108e9a563c7f97eda8ac8c3fff08dc065d8734cfa57a1" nocase ascii wide
                        $string86_lolminer_offensive_tool_keyword = "fb3fc9cf96316c4e18a633564cfc32f0345a14ec544715fdeb23a8e773d7d46b" nocase ascii wide
                        $string87_lolminer_offensive_tool_keyword = "fdad34a59a97f03cc8b8da455730e1bf8557c95dcf866b38971afa75e0c34026" nocase ascii wide
                        $string88_lolminer_offensive_tool_keyword = /https\:\/\/github\.com\/Lolliedieb\/lolMiner\-releases\/releases\/download\// nocase ascii wide
                        $string89_lolminer_offensive_tool_keyword = "Running lolMiner from " nocase ascii wide
                        $string90_lolminer_offensive_tool_keyword = /ubiq\-eu1\.picopool\.org/ nocase ascii wide
                        $string91_lolminer_offensive_tool_keyword = /WALLET\=.{0,1000}\.lolMinerWorker/ nocase ascii wide

    condition:
        any of them
}