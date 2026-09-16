rule sha3_224_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4f9645c6ecf231432820a3334b276c11b746bd96b9b0e2932ef9a39"
    $a1="f4f9645c6ecf231432820a3334b276c11b746bd96b9b0e2932ef9a39"
    $a2="0e4729a46e76021dc02a90f365b845c17440a14f8d39e3a380eae46c"
    $a3="0e4729a46e76021dc02a90f365b845c17440a14f8d39e3a380eae46c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}