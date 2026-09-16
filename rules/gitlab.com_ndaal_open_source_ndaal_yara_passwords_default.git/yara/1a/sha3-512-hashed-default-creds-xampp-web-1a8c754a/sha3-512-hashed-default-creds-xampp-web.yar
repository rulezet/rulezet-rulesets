rule sha3_512_hashed_default_creds_xampp_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xampp_web."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6d88af8f648f7d8ff7e013fd2fa5d9a127cb6f544bf596acc278a3ab90072cee3aac533c7a584b0cabcba51a47132c6cec76e4447dfa047e6368469ad42ec31"
    $a1="ab04d145529d509c073f513c04c4593dcf360eb0ad172dfa0613d9c6fcc10e37b5a4f8e9102694c8ea018a5e58e97cea0c7c2731de2fcc268bd2b2c6fe4492b2"
condition:
    ($a0 and $a1)
}