rule sha256_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
    $a1="2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
    $a2="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a3="03dd899dee631fcc4ec032704623e7b612de6b00a72bddc2f5748b8c999ce4bd"
    $a4="5072cd21aff496b31d0ee9a4ddd4533775c24391d4fbb7e30b1bfd837c52b062"
    $a5="5072cd21aff496b31d0ee9a4ddd4533775c24391d4fbb7e30b1bfd837c52b062"
    $a6="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
    $a7="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}