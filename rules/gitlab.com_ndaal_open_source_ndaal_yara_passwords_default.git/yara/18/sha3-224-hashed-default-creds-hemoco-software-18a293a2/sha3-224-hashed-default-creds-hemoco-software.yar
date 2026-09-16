rule sha3_224_hashed_default_creds_hemoco_software
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hemoco_software."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="72a77bfd8fd21160833f3481c1b061d5d89a3e1731cca10d16e50c7f"
    $a1="c8c550837cb1bd484ec54177f469d9ecb71bdb10fd5023c4c7e16a6b"
condition:
    ($a0 and $a1)
}