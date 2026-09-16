rule sha3_512_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5886b2c57ad425f48ae63f8e3198f46a0700aa2c873d1ef287bd548ab3cbc13a91debc14476174c964335373296cf2cd1c7dd9953826cbfbfc29470bb7c7496"
    $a1="15a0ba31aa655fcc8d847b58402170934d96454a646aa67527b8c2c1a75791569507d1e6ade343e5513d34815ad411726aef691fac00fa8e5ed48c0b0395a371"
    $a2="b5886b2c57ad425f48ae63f8e3198f46a0700aa2c873d1ef287bd548ab3cbc13a91debc14476174c964335373296cf2cd1c7dd9953826cbfbfc29470bb7c7496"
    $a3="1afc6ee62646be541d4c94f4e60e6f6adb30658ff2b097999ffdb90c366a186fa35a2a5408278bb73379e7b76d48db3f515eb1e8734b1508f14da5ca7a14d7c5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}