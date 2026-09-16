rule sha512_hashed_default_creds_comcast_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comcast_smc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3da2b7056f0d39bb20a39339bcaae05851870a2385844b7347f7cb262c7fedf3e77c6604caa27ec58044e83e780c9b5c299622469f86c6180ebb7293dd20b7a8"
    $a1="4054fbcf8983db0ee83431df3913ce238d05177e8650a3a39c78394aedee99bd1efc32a8f96648bf00267c805bd82d5f6b870ee2a2eadb5314c5dcf7eb1f9e35"
    $a2="dc3283f0dcc070a4434448ab2bf8caaa3b546bb32ea44a1173c7f7fb896d21c087786050eef69ad3e7541b546ee7a8f61e163a5749de0089502a401e51f19b9e"
    $a3="4054fbcf8983db0ee83431df3913ce238d05177e8650a3a39c78394aedee99bd1efc32a8f96648bf00267c805bd82d5f6b870ee2a2eadb5314c5dcf7eb1f9e35"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}