rule sha384_hashed_default_creds_keyscan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for keyscan."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dc9f616ec309a570a8ebc5b7209fac4bd47cf9b759f39e7f7fe40be4d21022be5e6423f1377ee51a8fecb47a8c1e27e1"
    $a1="37250cbf78a7e39273a25eae54bf10f6edcfe414c61db87ca7e93c6d4cb0feb9219dc5e44edf13085afa81cb18cb9f12"
condition:
    ($a0 and $a1)
}