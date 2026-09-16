rule blake2s_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f11623c53c2151d2c3ecc2291f32a93aa363c101ebed6fdc0b4821e5c0538d5c"
    $a1="483eb8fe7845f16ae039c3886555ec01db8ee4d7f85ba5297aa2ea51f0d6cdb3"
    $a2="4fd1fbff45321b03a04f4be3da6f0c8705e62d43dbb3cd75a94f3d6122e4c717"
    $a3="6681c74838cb645934d7e8a8c8a510e714e10cff422f28f9e6b1aa712be98f02"
    $a4="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
    $a5="4ed0966db6c4db5afd7852d3103540e7c2237f5e0fda8bcbbab683dee07fe3fc"
    $a6="fafb96c8f2dacb1eb883d9fd7ffce1ca512d0a2f964e2a5674fdcbea01a29a98"
    $a7="f137411b263f529b8021a6fcc3cf7e9ff325fa0f80a189b555fadec8e6ca1953"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}