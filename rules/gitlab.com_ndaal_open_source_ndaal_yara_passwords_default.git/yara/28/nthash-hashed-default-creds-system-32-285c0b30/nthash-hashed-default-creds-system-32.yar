rule nthash_hashed_default_creds_system_32
{
    meta:
        id = "EQ7JE1YBAsUHnpYnOmqyH"
        fingerprint = "31ef7df643169c6cb94263a8db03cea4bd93cf06e1f7a6a06c785ec22d02f965"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for system_32."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="878d8014606cda29677a44efa1353fc7"
    $a1="e5fc8b7cb519f6a41bd61c5293ef8df7"
condition:
    ($a0 and $a1)
}