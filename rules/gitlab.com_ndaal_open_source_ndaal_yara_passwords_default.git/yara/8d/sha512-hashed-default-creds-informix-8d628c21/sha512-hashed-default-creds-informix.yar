rule sha512_hashed_default_creds_informix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for informix."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="01389b520d126884faf146cb0c871a9879f75dc643c26c98fd2a32b33d8661cf4d230b56c00420ab82d87847946e387094505a3325da772e059e3b61e4a89830"
    $a1="01389b520d126884faf146cb0c871a9879f75dc643c26c98fd2a32b33d8661cf4d230b56c00420ab82d87847946e387094505a3325da772e059e3b61e4a89830"
condition:
    ($a0 and $a1)
}