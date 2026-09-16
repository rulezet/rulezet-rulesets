rule sha3_384_hashed_default_creds_netbotz
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for netbotz."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e081fae0567fcbf4c11bfa5d43e06af76928327bba6983185be1c2a34f7772a214921305504ae0ee0eeb8c8094811fb"
    $a1="6e081fae0567fcbf4c11bfa5d43e06af76928327bba6983185be1c2a34f7772a214921305504ae0ee0eeb8c8094811fb"
condition:
    ($a0 and $a1)
}