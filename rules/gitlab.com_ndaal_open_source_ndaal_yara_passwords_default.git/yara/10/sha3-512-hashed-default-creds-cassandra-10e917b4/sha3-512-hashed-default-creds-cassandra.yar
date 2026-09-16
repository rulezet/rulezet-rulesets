rule sha3_512_hashed_default_creds_cassandra
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cassandra."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9e502029eed73376ac2a058f1f7cd7c44e6c0bf9a6a4448a1d0171336b48e96eadefe02cecef3d7d5bad793d29ba9a93d7d2ae7bd807695da47351486d6f3fe2"
    $a1="9e502029eed73376ac2a058f1f7cd7c44e6c0bf9a6a4448a1d0171336b48e96eadefe02cecef3d7d5bad793d29ba9a93d7d2ae7bd807695da47351486d6f3fe2"
condition:
    ($a0 and $a1)
}