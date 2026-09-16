rule blake2b_hashed_default_creds_phpreactor
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for phpreactor."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f67991b83f5325d369868d4e770764605cabbd69bb6ef7ff5aa310fa83dbcb99f3013e024e0f1e6d14e687d96b64ae3bf38f528cdb29b0b848154b01c022b4f1"
    $a1="0e89533ae07f2b649d869018b12e53af8c5da84a479e5899bf9536654cc94d91c7bd731e6f28cddab2c58e8e6279c2b4feb14bb5aba26358d946ccb2496fcc4a"
condition:
    ($a0 and $a1)
}