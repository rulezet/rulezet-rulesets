rule sha3_224_hashed_default_creds_nevisidm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b20a271233d223a5a78f423751110a33b782c4e97a6455d31fb3acdf"
    $a1="f331b466b582a8f60e6088c98e57b08ab64db01abf40cc90c34826e4"
condition:
    ($a0 and $a1)
}