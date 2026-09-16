rule sha512_hashed_default_creds_comodo_group_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for comodo_group_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61f2c2a4060df5548f43459575894a351035a87b3be2193ec4dc0e22669812d1d173907f7660142be4ba30ae9b5ee8dc99387ddec0dc329cdee196e16cd360f5"
    $a1="61f2c2a4060df5548f43459575894a351035a87b3be2193ec4dc0e22669812d1d173907f7660142be4ba30ae9b5ee8dc99387ddec0dc329cdee196e16cd360f5"
condition:
    ($a0 and $a1)
}