rule sha256_hashed_default_creds_huawei_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for huawei_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a3="c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f"
    $a4="94f6682f71fc007700c2190785710092ec7d0c59cec689e67bd77a20f6ac418b"
    $a5="94f6682f71fc007700c2190785710092ec7d0c59cec689e67bd77a20f6ac418b"
    $a6="22358b6af3977915e7d095ee76a8a572e952adda4fab9e8e8841042d806afa27"
    $a7="bc979c4710136670e77b88916412901b7926e454626910433ba52db89e287f82"
    $a8="5213f4cb8a72d3908b4ac8b665e09f23bcd8dd01c41395de403106ae3cbf7c9b"
    $a9="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a10="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a11="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a12="c09dee99967309b12c066143a662efd5fc01f4b628d337037dcdf3931c0661bc"
    $a13="c09dee99967309b12c066143a662efd5fc01f4b628d337037dcdf3931c0661bc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}