rule sha3_512_hashed_default_creds_tellabs
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tellabs."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f73bc61e5e901a9bc89e72d464e4fe18eeb41c4e25c00cd2f0e5e7a450b237632648e2ccce32b26e615236622c8f611a470a9d48df757b6636ef504974f20039"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="dc04911c76e674867cd3f71778b8dbeea1ceda90d6cfd0054db2ac81a399238820c9aafcbf92d3e4cfb8551c1d1ccd7bea1b9eb0d7914a019ac3b01d6e7c2cd4"
    $a3="e2699b363ba2601552e587119d477f359e5d14a9cbe62fb0d1d7c74b1b084cf84cf1ce556e0d1fe9d280aa207f40e7e7575cd689cc70c4362c3552c256f26061"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}