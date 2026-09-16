rule sha3_384_hashed_default_creds_tandem
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tandem."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="06ff6516b10e34580acbb5f2b05ae2628cc1c661fbb3e50b31dac0d0fc5be94784163e820aed296a54555a0d4ecd0190"
    $a1="8c9774089b8e3840648e1a38bf1a0f5c8d884211a39d8e8bbf5b1bedec03f0cc7523a1a5c78328e615088389ae9c8f2a"
condition:
    ($a0 and $a1)
}