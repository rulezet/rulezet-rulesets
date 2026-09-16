rule sha512_hashed_default_creds_barco
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barco."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6957d074e9fb020da977127a605a641ddfabd59a2df0a76fa316ce40659f614de904acb82970ba98aa44131a58431577c314f7040eb2da4a7b1c86dfde177a"
    $a1="dd1c7a428d71fb57f9b0f39a7173cca278e0ddb38ef95e01867ecb6ca537d361ccc9cb3778c0dcf82ff621f9ca65c61cf2852581e571e5de38ff1ee556a0cfd8"
condition:
    ($a0 and $a1)
}