rule sha3_512_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="baf9cd37fc5c34e635729b68f94e26a6a95d44fc97aded2731fb514dd05c53266f88ce4dffcf31f07aaa9b6551ae8447f3dd4b6e67dcc7de6d93be9e7fa80aa7"
    $a1="7d82e8deff52c99abe279678f98e50cd2c70edf53bd4c847f324c380cee7ade9f036315b79fac6c1c17c6b05827894ade1a422e46a4325269eb9bbd06a48e6a7"
condition:
    ($a0 and $a1)
}