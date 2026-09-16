rule sha512_hashed_default_creds_aris_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e6fab89ebb13868b5d85f327ad3ac8f23b1fd26a9f6b88fc6c3cb4820ba3dc97ca9531a6b3b08b95394b8780a831aea29bf3b1c5121963fa0229a3795d58db6"
    $a1="f6e16adaef97f1a0856e11027a4cc5568605d91d31a64ce3766011f3d0d04e51194ac07197e34cd012eb27c238027756ee914c65b6c13ece5de8a79e104a2a32"
condition:
    ($a0 and $a1)
}