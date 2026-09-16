rule sha3_224_hashed_default_creds_voicegenie_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for voicegenie_technologies."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="708ef04755d85fb4a2340edc89f78a21574248bc4dbb568eb907c3a2"
    $a1="708ef04755d85fb4a2340edc89f78a21574248bc4dbb568eb907c3a2"
condition:
    ($a0 and $a1)
}