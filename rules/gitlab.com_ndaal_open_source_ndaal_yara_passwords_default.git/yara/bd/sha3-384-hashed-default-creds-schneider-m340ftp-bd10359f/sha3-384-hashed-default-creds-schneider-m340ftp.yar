rule sha3_384_hashed_default_creds_schneider_m340ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider_m340ftp."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1982f42589842b2044a81748873969acbc6ab0b28305259651b29c6a3dbe9e17515dd60ea81dd506ad0a6df96e048726"
    $a1="46d4665406a2b67de50adfa819779a33d776eb80884c016b31f2d9d12bc3f584f8d1ad18f9da4efd4618b6f18dd6ebdd"
condition:
    ($a0 and $a1)
}