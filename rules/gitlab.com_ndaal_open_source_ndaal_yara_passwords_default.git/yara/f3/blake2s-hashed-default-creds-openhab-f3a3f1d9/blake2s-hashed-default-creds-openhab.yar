rule blake2s_hashed_default_creds_openhab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openhab."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be5e794db2bb2f6814ede107e7d2b9fa8a111f41b50d4b82d5e4763bcb8dff77"
    $a1="be5e794db2bb2f6814ede107e7d2b9fa8a111f41b50d4b82d5e4763bcb8dff77"
    $a2="a5288b9aa31c782882b5d20ba2f32a780eecbe9f60622c91b74c2d36bcf6dfea"
    $a3="311fb1ea3d1821bcd70c6c40cebe38ebfa2321d9c61def00d63a4b39e5cd5e17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}