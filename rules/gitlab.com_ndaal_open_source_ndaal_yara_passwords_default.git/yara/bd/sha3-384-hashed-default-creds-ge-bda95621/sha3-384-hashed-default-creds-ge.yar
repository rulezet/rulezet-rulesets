rule sha3_384_hashed_default_creds_ge
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ge."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3cf17e66e6ca7f00b3e7da8efaa5db4ad65eb292265b6c0a6ad2cf22ecd93aecc0a09fa40f88492041539a854217c598"
    $a1="c48349c787469982a2d5bd2510e3d4f3481db7dd8c523c3defb730ef0b1831a703d530efd63b04baed52a8abfb8eb4d0"
condition:
    ($a0 and $a1)
}