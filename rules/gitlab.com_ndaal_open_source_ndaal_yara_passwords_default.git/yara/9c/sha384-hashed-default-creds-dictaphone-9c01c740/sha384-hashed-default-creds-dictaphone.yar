rule sha384_hashed_default_creds_dictaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1dc4fce6e46b62d31fe29f5a5ca51c2b4f3db5ef8d58cec9d7bba4a4a99978959f4637730df6287852eac2243495aa39"
    $a1="1dc4fce6e46b62d31fe29f5a5ca51c2b4f3db5ef8d58cec9d7bba4a4a99978959f4637730df6287852eac2243495aa39"
    $a2="bc682477e61c4a8a71a1777b0151a1842c02e474220975fdec86c2fd8cf932e9caacf552eb2a999117b26172b8edd4e5"
    $a3="bc682477e61c4a8a71a1777b0151a1842c02e474220975fdec86c2fd8cf932e9caacf552eb2a999117b26172b8edd4e5"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}