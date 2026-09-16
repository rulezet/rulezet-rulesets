rule sha512_hashed_default_creds_aspect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aspect."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c71ecac0817cb2e13de19fe11b79bb6c2b6f0febc3b1656205275f691c01b8c0e6ef9a70f8dafc56e4516fab16e519cdcceee3d58e7214de34df35cf436f343a"
    $a1="cb227f47afe814cab9c9d019a8613751d1bd25eafe152afed284e118b58b0078a8c49f0bb7fe912f381c55f257bd8b4ef6bec4b5256cf9ccb8f107cec23e88cc"
condition:
    ($a0 and $a1)
}