rule sha512_hashed_default_creds_lenel_onguard_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lenel_onguard_mssql."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9287cd7f4e78efc389baf282f685289a8b3943e5168af2dd3fa2a45f55eebc75d9c7f1148161f8916dcdd1d059bbcb13c7de7923aa8f13ed1c204da3654e7b45"
    $a1="2c43b432a31485229457525cfbd4af71c10d6a4e13c19e9c610f9b266be8feada0c201e57d60e0270a3b6a3d0a7d935ee4409ee4a74df73e086a0b05fda46363"
condition:
    ($a0 and $a1)
}