rule sha3_256_hashed_default_creds_carel
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carel."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ce879e5ecffd8bdd8708ad528b127fdc5af62bad9391abeea3cebd5e5c15c6a"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="6f4e7231414dd68f72281c05e2febce9570c7afd82849bf72ec655d2bf06b968"
    $a3="7b0259861f4636043c6ba8ac0462e5a6d28b62b18f466e06c181a118bd33660b"
    $a4="da056aa026df9262cc36c7dd75546dba5eb3d1772eb38688deb4032bdc1990ff"
    $a5="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a6="d40bc53ccb3df613131e72e46c8bbb2bc05030a02cf4ac81223dfc224ee03f8f"
    $a7="ec4a58942b4dac0953dc886ad03288e9b98234285e670ce2da803a782a38c952"
    $a8="85e118c98aaaa18fa295ad12e12929effe564a02d625d5a20e21503a60a894bb"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a10="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="f7649aa351d3e686a0a534623b441bc90cd9e527aceb9d03efc43bb42b3138ac"
    $a13="8f775eebf93f2f6fa2d5b0e6488550621b7d027f6d212799bbe60b991f70640d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}