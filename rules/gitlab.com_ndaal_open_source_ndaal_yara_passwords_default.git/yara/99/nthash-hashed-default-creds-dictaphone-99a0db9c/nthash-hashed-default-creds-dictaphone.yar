rule nthash_hashed_default_creds_dictaphone
{
    meta:
        id = "2cRLrVfPjQKYXU1Dega7Ei"
        fingerprint = "35c176fa60a91c3e6aa8807ea2aa0ecc9b0df5a8cb48504cf99c53ddeddbf4ce"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dictaphone."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4f86769771ef26b6fb2fa00aa7f1ffc5"
    $a1="4f86769771ef26b6fb2fa00aa7f1ffc5"
    $a2="03b2f73d716f9174fbb4ba4f646e4c32"
    $a3="03b2f73d716f9174fbb4ba4f646e4c32"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}