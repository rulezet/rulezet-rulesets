rule ldap_sha1_hashed_default_creds_mssql_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mssql_mssql."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}x45HZ1Hua9AFbZ1cbGuVliR4TvQ="
    $a1="{SHA}rjgRUVM/lhejsJtso/ov1rEzTkE="
    $a2="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
    $a3="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a4="{SHA}sumK1vbrhQjdahTPpwS61/Bfb7E="
    $a5="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a6="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a7="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
    $a8="{SHA}jQyoJV1zBeE6kYXKhmaoLXphkI4="
    $a9="{SHA}Ngim0aBauiPqOQ5fO0ggPbtyQfc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}