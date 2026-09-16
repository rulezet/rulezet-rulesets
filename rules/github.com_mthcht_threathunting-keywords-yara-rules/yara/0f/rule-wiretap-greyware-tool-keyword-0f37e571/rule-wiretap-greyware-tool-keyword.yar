rule rule_wiretap_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wiretap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiretap"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_wiretap_greyware_tool_keyword = " install wireguard" nocase ascii wide
                        $string2_wiretap_greyware_tool_keyword = " install wireguard-tools" nocase ascii wide
                        $string3_wiretap_greyware_tool_keyword = " pacman -S wireguard-tools" nocase ascii wide
                        $string4_wiretap_greyware_tool_keyword = /\swireguard\-installer\.exe/ nocase ascii wide
                        $string5_wiretap_greyware_tool_keyword = /\swiretap\.exe/ nocase ascii wide
                        $string6_wiretap_greyware_tool_keyword = /\.\/chisel\sclient\s/
                        $string7_wiretap_greyware_tool_keyword = /\.\/wiretap\sremove/
                        $string8_wiretap_greyware_tool_keyword = /\/Wireguard\.zip/ nocase ascii wide
                        $string9_wiretap_greyware_tool_keyword = /\/wireguard\-amd64\-.{0,100}\.msi/ nocase ascii wide
                        $string10_wiretap_greyware_tool_keyword = /\/wireguard\-installer\.exe/ nocase ascii wide
                        $string11_wiretap_greyware_tool_keyword = /\/wireguard\-installer\.rar/ nocase ascii wide
                        $string12_wiretap_greyware_tool_keyword = "/wiretap add client"
                        $string13_wiretap_greyware_tool_keyword = /\/wiretap\.conf/
                        $string14_wiretap_greyware_tool_keyword = /\/wiretap\.Dockerfile/ nocase ascii wide
                        $string15_wiretap_greyware_tool_keyword = /\/wiretap\.exe/ nocase ascii wide
                        $string16_wiretap_greyware_tool_keyword = /\/wiretap\.git/ nocase ascii wide
                        $string17_wiretap_greyware_tool_keyword = /\/wiretap\.log/
                        $string18_wiretap_greyware_tool_keyword = "/wiretap/releases/download/" nocase ascii wide
                        $string19_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_linux_386\.tar\.gz/
                        $string20_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_linux_amd64\.tar\.gz/
                        $string21_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_linux_arm64\.tar\.gz/
                        $string22_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_linux_armv6\.tar\.gz/
                        $string23_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_windows_386\.tar\.gz/ nocase ascii wide
                        $string24_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_windows_amd64\.tar\.gz/ nocase ascii wide
                        $string25_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_windows_arm64\.tar\.gz/ nocase ascii wide
                        $string26_wiretap_greyware_tool_keyword = /\/wiretap_.{0,100}_windows_armv6\.tar\.gz/ nocase ascii wide
                        $string27_wiretap_greyware_tool_keyword = /\/wiretap_relay\.conf/
                        $string28_wiretap_greyware_tool_keyword = /\/wiretap_relay_1\.conf/
                        $string29_wiretap_greyware_tool_keyword = /\/wiretap_server\.conf/
                        $string30_wiretap_greyware_tool_keyword = /\/wiretap_server_1\.conf/
                        $string31_wiretap_greyware_tool_keyword = /\\WireGuard\.lnk/ nocase ascii wide
                        $string32_wiretap_greyware_tool_keyword = /\\Wireguard\.zip/ nocase ascii wide
                        $string33_wiretap_greyware_tool_keyword = /\\wireguard\-installer\.exe/ nocase ascii wide
                        $string34_wiretap_greyware_tool_keyword = /\\wireguard\-installer\.rar/ nocase ascii wide
                        $string35_wiretap_greyware_tool_keyword = /\\wiretap\.exe/ nocase ascii wide
                        $string36_wiretap_greyware_tool_keyword = /\\wiretap\.log/ nocase ascii wide
                        $string37_wiretap_greyware_tool_keyword = "<Data Name='Product'>WireGuard" nocase ascii wide
                        $string38_wiretap_greyware_tool_keyword = ">WireGuard Relay<" nocase ascii wide
                        $string39_wiretap_greyware_tool_keyword = ">WireGuard Tunnel<" nocase ascii wide
                        $string40_wiretap_greyware_tool_keyword = ">wireguard-installer<" nocase ascii wide
                        $string41_wiretap_greyware_tool_keyword = "0164502183613e987753f77bf9a45bde5a08f9332cf2d119cbfbf284cae64a25" nocase ascii wide
                        $string42_wiretap_greyware_tool_keyword = "0183a78b64841b968eac59c0c912ecb0c44ec0ccdd773e422c6529d4e0ea5ca3" nocase ascii wide
                        $string43_wiretap_greyware_tool_keyword = "071c1ac9622484472732bfb85fdf11bf4a62d70d4f5d2aeed5a92e9e8be51346" nocase ascii wide
                        $string44_wiretap_greyware_tool_keyword = "072c59c3bc429c761425c680611cc35c189582d6837d4b2bd205c648722b51de" nocase ascii wide
                        $string45_wiretap_greyware_tool_keyword = "0b3128b7117e4575cd58267525750053b8ad2abbff38d586faa4e2b72c7a31db" nocase ascii wide
                        $string46_wiretap_greyware_tool_keyword = "0fe131b5d680b328dd8c3286d6c300b0bd606373d3a2de0e6ebec613528bf65d" nocase ascii wide
                        $string47_wiretap_greyware_tool_keyword = "106be837e5aca74895a290d85bbcf90f95e4613f41de7d28f9fc834d8f34afad" nocase ascii wide
                        $string48_wiretap_greyware_tool_keyword = "12d9cf76e82ea590777ee552a9ff96a10b6304df20b141bb2dc7bdf054be8402" nocase ascii wide
                        $string49_wiretap_greyware_tool_keyword = "14ac418b893997f60d07f0b2ce81ac979ec6ba849664de462cef5c6c720e93f3" nocase ascii wide
                        $string50_wiretap_greyware_tool_keyword = "1c7b04e5a15afed07071240ef6dfda584aede9f24e333463b6e00cdaa3886fc5" nocase ascii wide
                        $string51_wiretap_greyware_tool_keyword = "1caf54aea406542836d678b35daef36f7dab5c6b271cc9333bf9132fb9a11b5a" nocase ascii wide
                        $string52_wiretap_greyware_tool_keyword = "256ade9e6d03ca6e485f0932c122dbd226762d2c29c07414d0dc1dcac2a4eb0b" nocase ascii wide
                        $string53_wiretap_greyware_tool_keyword = "2d042ee6e000dbf50b37b2fe8a77fb8cc71de9b4beb0f6f902b4d0885ae8facf" nocase ascii wide
                        $string54_wiretap_greyware_tool_keyword = "2d87b8f3d0a56c9e101271c83e0b4c8f243af14a10965619d037210900304dde" nocase ascii wide
                        $string55_wiretap_greyware_tool_keyword = "35fb32ecde0afcac0b1feb446052674763484264adae6c09148f4a0c7adac433" nocase ascii wide
                        $string56_wiretap_greyware_tool_keyword = "5141adc9e35e695f849f9f2a7749a428263d1a02e1efdf24547f53596be97a25" nocase ascii wide
                        $string57_wiretap_greyware_tool_keyword = "64601caa675146be542b3e4c658019f9c443c8fa64a898985aa691eab5c5037d" nocase ascii wide
                        $string58_wiretap_greyware_tool_keyword = "671eaebafae768f136c85087dca3ecc2068283e611f62345d152d843cfcf02ea" nocase ascii wide
                        $string59_wiretap_greyware_tool_keyword = "6e44d4eec61c35b14e9e43158b8a169269a98be0e2ae8992cdb0a50ea09b97a1" nocase ascii wide
                        $string60_wiretap_greyware_tool_keyword = "74ce40c0871314e1308984b12d93161faf806f6d508dd256678f09af1abc1052" nocase ascii wide
                        $string61_wiretap_greyware_tool_keyword = "7ca32274aad66276fcbc12b50158356781277aa4efc50eee49c10f2eac192cef" nocase ascii wide
                        $string62_wiretap_greyware_tool_keyword = "831096dedc1741e97c5a65d992cf8825a02bdcd43c76727d2a9d26638cfeedd3" nocase ascii wide
                        $string63_wiretap_greyware_tool_keyword = "8432faf9d944bcf430ebb7d45282f84901a59eb5e4ae3fc9b7ba5226b7a4ce35" nocase ascii wide
                        $string64_wiretap_greyware_tool_keyword = "8fcc7cb6eee6a29804ae22281e0477c47de9a924bd7beb9bed24f7c1d84d8a9d" nocase ascii wide
                        $string65_wiretap_greyware_tool_keyword = "9a6975a16e6abee257353caa0216c7ee50aed1618cb05c73ee105ecd07e0bdf3" nocase ascii wide
                        $string66_wiretap_greyware_tool_keyword = "a059a3d56743994d8f3996e05725957ebb5099c97bdd8ee92ed739f552073f46" nocase ascii wide
                        $string67_wiretap_greyware_tool_keyword = "aa660d59e6c7783ebb9d4244d3991392ab602cd4fcd06457656bed2f61b7b51a" nocase ascii wide
                        $string68_wiretap_greyware_tool_keyword = "b1a6f85aa7693abc888ec5cd0313b16ae5e932dee4e04f495481935530276427" nocase ascii wide
                        $string69_wiretap_greyware_tool_keyword = "b710bdc87555b125cca39a89d2f41449b99afa567ec7e78f6e28b3f7bf872ac3" nocase ascii wide
                        $string70_wiretap_greyware_tool_keyword = "c88212e7221a28d2877ba03c01c5df776c61aa4e36bc5a5909bceea7545fdfb1" nocase ascii wide
                        $string71_wiretap_greyware_tool_keyword = "chisel server --port " nocase ascii wide
                        $string72_wiretap_greyware_tool_keyword = "d04679accb8ad4bbd940d7afcb4d2765c3ea1421bb773b71e79f3f0233f847cd" nocase ascii wide
                        $string73_wiretap_greyware_tool_keyword = "d520c8bd60a9f8da3a90b1b47194dfb17df78554a97de633fda813c0152c01b1" nocase ascii wide
                        $string74_wiretap_greyware_tool_keyword = "d59838007c4724beca80ad34c6adc749c526f6de636d79e06565499d0e390110" nocase ascii wide
                        $string75_wiretap_greyware_tool_keyword = "docker exec -it wiretap-client-1 bash"
                        $string76_wiretap_greyware_tool_keyword = /download\.wireguard\.com\/windows\-client\// nocase ascii wide
                        $string77_wiretap_greyware_tool_keyword = "eeee2b0a6ad1c7e4614fed4dfbe58b63776f6a3a6758267b5a976b4dc4315f48" nocase ascii wide
                        $string78_wiretap_greyware_tool_keyword = "f9ddbf1047c9a2e24310e5dc68508504c69e037e47c624f32b4d25ff8b30ed87" nocase ascii wide
                        $string79_wiretap_greyware_tool_keyword = "fc901b9f783876c3cb057dbed28b5612fd376963f148d1375bb0c8cf86bb2e10" nocase ascii wide
                        $string80_wiretap_greyware_tool_keyword = /https\:\/\/www\.wireguard\.com\/install/ nocase ascii wide
                        $string81_wiretap_greyware_tool_keyword = "sandialabs/wiretap" nocase ascii wide
                        $string82_wiretap_greyware_tool_keyword = "WireGuard/wireguard-go" nocase ascii wide
                        $string83_wiretap_greyware_tool_keyword = "wiretap add client --port " nocase ascii wide
                        $string84_wiretap_greyware_tool_keyword = "wiretap add server --" nocase ascii wide
                        $string85_wiretap_greyware_tool_keyword = "wiretap configure --" nocase ascii wide
                        $string86_wiretap_greyware_tool_keyword = "wiretap expose --dynamic" nocase ascii wide
                        $string87_wiretap_greyware_tool_keyword = "wiretap expose list" nocase ascii wide
                        $string88_wiretap_greyware_tool_keyword = "wiretap expose --local " nocase ascii wide
                        $string89_wiretap_greyware_tool_keyword = "wiretap serve -f " nocase ascii wide
                        $string90_wiretap_greyware_tool_keyword = "WIRETAP_E2EE_INTERFACE_API" nocase ascii wide
                        $string91_wiretap_greyware_tool_keyword = "WIRETAP_E2EE_PEER_ENDPOINT" nocase ascii wide
                        $string92_wiretap_greyware_tool_keyword = "WIRETAP_E2EE_PEER_PUBLICKEY" nocase ascii wide
                        $string93_wiretap_greyware_tool_keyword = "WIRETAP_RELAY_INTERFACE_IPV4" nocase ascii wide
                        $string94_wiretap_greyware_tool_keyword = "WIRETAP_RELAY_INTERFACE_IPV6" nocase ascii wide
                        $string95_wiretap_greyware_tool_keyword = "WIRETAP_RELAY_PEER_ALLOWED" nocase ascii wide
                        $string96_wiretap_greyware_tool_keyword = "WIRETAP_RELAY_PEER_PUBLICKEY" nocase ascii wide
                        $string97_wiretap_greyware_tool_keyword = /yum\sinstall\s.{0,100}wireguard\-/ nocase ascii wide
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