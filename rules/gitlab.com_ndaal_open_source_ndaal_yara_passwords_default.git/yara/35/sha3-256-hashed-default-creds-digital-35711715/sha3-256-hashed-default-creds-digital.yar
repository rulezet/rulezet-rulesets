rule sha3_256_hashed_default_creds_digital
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for digital."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ac749fcf0ec9a7b07755f5228edf9a872ce6665868c6a4693aa88ec408ea072"
    $a1="b1b1bd1ed240b1496c81ccf19ceccf2af6fd24fac10ae42023628abbe2687310"
condition:
    ($a0 and $a1)
}