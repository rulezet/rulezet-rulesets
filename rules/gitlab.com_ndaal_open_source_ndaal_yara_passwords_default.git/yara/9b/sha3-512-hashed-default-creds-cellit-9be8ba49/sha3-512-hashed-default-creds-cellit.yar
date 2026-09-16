rule sha3_512_hashed_default_creds_cellit
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cellit."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90b71decf58039a87310db6392b829c319e8ff6cd60e5c35f519757d16b55fbb25d6f3d509305cea7a8ed363811499b3bf2729c0ef4d39b6dd2369b1eb59143f"
    $a1="90b71decf58039a87310db6392b829c319e8ff6cd60e5c35f519757d16b55fbb25d6f3d509305cea7a8ed363811499b3bf2729c0ef4d39b6dd2369b1eb59143f"
condition:
    ($a0 and $a1)
}