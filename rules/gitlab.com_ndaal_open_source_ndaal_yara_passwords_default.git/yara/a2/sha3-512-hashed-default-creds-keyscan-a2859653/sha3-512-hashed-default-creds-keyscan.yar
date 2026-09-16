rule sha3_512_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4353bd5838da494f1212aa040c2738d7285a87d9590752893ba958d4ba43d5c126baea82df977419a6d7437f5be05602f2484591aec3e44efe7fb0d216f9a999"
    $a1="680ef530485de33cd370f3b8c26cb1c644b168a522d83c97d9227736e75adee2627af14898c65c90eea83125aa92dc88827e7946cbca9fc214fa26cdc4b1c21b"
condition:
    ($a0 and $a1)
}