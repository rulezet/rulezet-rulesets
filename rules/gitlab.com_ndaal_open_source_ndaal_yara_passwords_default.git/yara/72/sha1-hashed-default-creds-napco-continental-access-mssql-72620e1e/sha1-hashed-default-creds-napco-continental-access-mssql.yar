rule sha1_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a1="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a2="e40a8cd471942491b9b412a517d6fd815ca5f45b"
    $a3="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a4="3d6acf5b0664c8422c6c0afa7ed1d39ff155ca2a"
    $a5="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a6="b0096e0c0be45b11a10cec30e461fbe9398b2ce1"
    $a7="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a8="e40a8cd471942491b9b412a517d6fd815ca5f45b"
    $a9="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
    $a10="3d6acf5b0664c8422c6c0afa7ed1d39ff155ca2a"
    $a11="3608a6d1a05aba23ea390e5f3b48203dbb7241f7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}