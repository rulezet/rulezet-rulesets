rule blake2b_hashed_default_creds_tekelec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tekelec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62ee14697e16b5fd419cebf793537af17c124bf70a44bde2daaf4ce00a78c5593fbb1fc77da0c6545d703a0bc2070018db9039473bea3dba753b361ef7f4652c"
    $a1="62ee14697e16b5fd419cebf793537af17c124bf70a44bde2daaf4ce00a78c5593fbb1fc77da0c6545d703a0bc2070018db9039473bea3dba753b361ef7f4652c"
condition:
    ($a0 and $a1)
}