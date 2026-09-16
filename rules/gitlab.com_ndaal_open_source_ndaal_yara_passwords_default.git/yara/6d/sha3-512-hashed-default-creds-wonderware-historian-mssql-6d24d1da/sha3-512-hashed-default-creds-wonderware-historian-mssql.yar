rule sha3_512_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="88d5d2e85e64b89ae2d15cb81a1cb32c103bb5bf22e96df4841578a0ac108fb50d48d8dfeeafab9a848a07af9b68e6da5443d4b9b67aa165ebd3375ba84020ba"
    $a1="984f8ad241aa596b695538ce3a5815cb8b75cdf87b34b1e7906d43e58dc96820c9c318afcfbe12b831f5e2ab98593af3985abce589a0746614caab9df3876e9c"
    $a2="8c581aab5237bab71a1c3d6047ad32a842acea079287555a19d417351bf74a1ad0d33d608efe8650e2136ed386c6dfe6915878483c92fddd69759d8c47d0ee80"
    $a3="1db3d23f9d03d1955698c98968f5f06223acb1dcb55706dd43698dbb57d40d220e763238328841eba9219aaeb88b5bd2072748b18d5c4f6512f0bf8370fff9cf"
    $a4="12facfe624b97ebb17ec8ee049582d5c1c4b06af8f48b205c7d9bc5c25fa7ae12394fed6da1070827bc42a479f45a4986c360533e9c90664f2216cf6518e2c9d"
    $a5="6b548c74eb1cc959f6203d02beb7ee57b93a470cffc79a0984e2b5cfcdb6b96824706dfd498cb8a5a2d9de56893e68d7dc214fa0582fc645e9ede58dddea2a7c"
    $a6="7abef5154be564d5c01b086595251be5ed857b65a6fb54bccfb55945e8f22195bd44d6c02ebffa66887fb0a9205784e86947cd6ae4bc1fe7690ece41ba957e67"
    $a7="7400ee86e9ec26ebd88f4b9d950e808b6ead36690f7e2505d7babe0c23a49dcf44ae346332e1d7691120b2f6a745e5243862157d3112821aadbdfb5ab697afa7"
    $a8="1849ea9a31d62cdcd93808a2217b782705617f740a63e1e23698aeb8b0263cf4059d710cd1fd0db34d9b3a43ed7936365fd57a0a50aca9340ce1db262191be86"
    $a9="1849ea9a31d62cdcd93808a2217b782705617f740a63e1e23698aeb8b0263cf4059d710cd1fd0db34d9b3a43ed7936365fd57a0a50aca9340ce1db262191be86"
    $a10="2b491ad7e03e6c59960d9d37e4800857b963c618d0bb6e175ec17d6e5d6d5a945e36929e5e42ad45c0914c89c94f822284f33aecf135c9368f3e0f2a7d2d656b"
    $a11="2b491ad7e03e6c59960d9d37e4800857b963c618d0bb6e175ec17d6e5d6d5a945e36929e5e42ad45c0914c89c94f822284f33aecf135c9368f3e0f2a7d2d656b"
    $a12="835177b2932f2522fe068b2abf7eb3cf267ec47d5e644b30e142e00d0d23bcc62135f5aa0b47b0a0920967bc73f133c327f37638443923b4557fe9a77eaf6755"
    $a13="835177b2932f2522fe068b2abf7eb3cf267ec47d5e644b30e142e00d0d23bcc62135f5aa0b47b0a0920967bc73f133c327f37638443923b4557fe9a77eaf6755"
    $a14="dd568ed1f071c04b3b4c35a893d3fbb0ec7cb53172a259cd36e4a78cb0de65cba25a95f03b450315fdb37ab226b4cf386f93e84b13d18c0d47932c2b629d6fe4"
    $a15="dd568ed1f071c04b3b4c35a893d3fbb0ec7cb53172a259cd36e4a78cb0de65cba25a95f03b450315fdb37ab226b4cf386f93e84b13d18c0d47932c2b629d6fe4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}