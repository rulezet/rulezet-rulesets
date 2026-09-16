rule sha384_hashed_default_creds_nevisidm
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for nevisidm."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0219e403de8f8c0b3569f8bec9cf591524639506a4b9313a790fcab11c79e2fbda0317d6b136f67949126dbe11be62bf"
    $a1="e2b7c7854abdcc42df3436106f858f40174d421f69d38c633a539828975b0b5dbfc62d98ebb1f071501144c53d48c3dd"
condition:
    ($a0 and $a1)
}