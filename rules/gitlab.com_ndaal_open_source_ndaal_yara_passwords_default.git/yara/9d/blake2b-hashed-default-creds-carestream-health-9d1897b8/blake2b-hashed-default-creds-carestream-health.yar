rule blake2b_hashed_default_creds_carestream_health
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for carestream_health."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d9eb91de64469dd192d4c556a8b049ae688e112e2527624d7d8df3a5688631aeb0acb244aa2075569c9bbea6046dae668608d0d0591abd070d8d5c633dd8c152"
    $a1="9734ffc964bf0ea6b6c10084adfbd2daab9b26b4bcc102255561b413de7c204be389cb5b47c8fc08db62dc585b8b757125a2da131f22ec6e760f9de68bfaa85b"
    $a2="d9eb91de64469dd192d4c556a8b049ae688e112e2527624d7d8df3a5688631aeb0acb244aa2075569c9bbea6046dae668608d0d0591abd070d8d5c633dd8c152"
    $a3="815eb5f4b9764f53c18f2541bd4e4b737bcaa8f319e74487db065f9f1ae8c14f340ca9f83f947c31fc28ae7fd22342e069a8bc019b3b6648c5ea16beb10b4a78"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}