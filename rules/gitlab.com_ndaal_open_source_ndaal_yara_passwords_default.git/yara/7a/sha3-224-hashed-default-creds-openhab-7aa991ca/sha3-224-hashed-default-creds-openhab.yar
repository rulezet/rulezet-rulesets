rule sha3_224_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="420b40bffd7a5ff52b149ca644c319b4a7c0843d9f71195f7c40a76e"
    $a1="420b40bffd7a5ff52b149ca644c319b4a7c0843d9f71195f7c40a76e"
    $a2="a34116f6b1325af05e5207c5997b3709f37d68b89ad38014db4b669e"
    $a3="b624c683caaacd81f112da860908bccdb04701751b121c9e5bac5973"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}