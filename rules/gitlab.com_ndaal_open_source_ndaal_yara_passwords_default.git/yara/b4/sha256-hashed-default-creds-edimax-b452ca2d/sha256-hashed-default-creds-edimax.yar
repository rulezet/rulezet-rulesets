rule sha256_hashed_default_creds_edimax
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for edimax."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="923a4787fabeed8844e722ca7cb20a61cdc049e7c21ddee3bd660d48c607eaed"
    $a7="1b10ca207d3a0ea152728b0a5f37387142c8d09b159abde99ad03616bfacc9ea"
    $a8="4dd98590f9dcdcdddaf268f443300ec1f63ddc8fb5a72e7b4bea2c0e4cc57014"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a10="1adb6b730147cfeb05c53de699867d15cfd04155a406ce9ea5eacda0227c4fb3"
    $a11="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a12="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"
    $a13="84983c60f7daadc1cb8698621f802c0d9f9a3c3c295c810748fb048115c186ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}