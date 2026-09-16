rule sha3_384_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a4="7abbd600252d0146f83b25df998af94b5a0e52ebc02f5354dbd46c5093b1d9f2616772dc826a081bdd5138d784e34296"
    $a5="7abbd600252d0146f83b25df998af94b5a0e52ebc02f5354dbd46c5093b1d9f2616772dc826a081bdd5138d784e34296"
    $a6="6ad53a5d9f18d6ceefb6ba49ce5ec13c48b90a41acfc3385dcb1a953be2f5e464ae535ca2e822a44e71eb3344981ab63"
    $a7="d4f7d21ee9a9f6c05bf277caf770f449f6cdd90cd78ed6f7438d6cfdfb3168d209b31d055350d2de7fbd29b9fd5d2d11"
    $a8="d960f28a178c05dbecab4339af88391ef996fbf19ae20c76d9b42c9606db91798edb6f29f8c91fb78a9ff7e079d63c75"
    $a9="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a10="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a11="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a12="f00ddbc4a4fae61d2c4216a2231b6941f9ef04715c899c86e5271a1604f97e2455aa11d7994cc4e9b2402413d9997276"
    $a13="f00ddbc4a4fae61d2c4216a2231b6941f9ef04715c899c86e5271a1604f97e2455aa11d7994cc4e9b2402413d9997276"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}