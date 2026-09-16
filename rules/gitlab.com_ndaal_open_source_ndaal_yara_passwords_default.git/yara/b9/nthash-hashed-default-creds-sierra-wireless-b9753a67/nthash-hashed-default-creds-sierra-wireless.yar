rule nthash_hashed_default_creds_sierra_wireless
{
    meta:
        id = "3Zdyt2xr12QFyUTrCN6ue6"
        fingerprint = "561603e34e46b9c894c6310a7b9d209cf2f760f253f4400dcd1e900fde7c5ed7"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sierra_wireless."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7a21990fcd3d759941e45c490f143d5f"
    $a1="57d583aa46d571502aad4bb7aea09c70"
    $a2="7a21990fcd3d759941e45c490f143d5f"
    $a3="ebc23363cf007b1e1562de99a6fe57ef"
    $a4="7a21990fcd3d759941e45c490f143d5f"
    $a5="ef0590d29f72ab21165637c451b10bb2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}