rule sha3_512_hashed_default_creds_mcdata
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mcdata."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="e34c71a03ea90304be4cc0b3c6356d5b6ef1596f97ee116ab205f616b70d1c6ee23a2d0276af6625ba658176e9ae9c92c3fef6686933dfde0efffd8d64a30494"
    $a2="a5fa98b254da9537e1a8eadd1c967c64921c3171231802de084394b1bfe8d0a6626a2ba897a8e8f3118d08ee2dcb21db26b474158c0927b1f03ec34972b48c58"
    $a3="0a8c846830cef7fc2cd989f3c01c8e9cda86ff0f6e8a91b706eae05771e79c9c6a96d8b9f16f76f60b4a3b4aa6d3e334227cf65b748b9d47ed3e41af1da52cd6"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}