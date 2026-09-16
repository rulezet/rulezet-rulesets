rule sha256_hashed_default_creds_webramp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for webramp."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="afbb04ce5a8f53828ceba2116dbdab56f610d159de235ad57ad2874adc8882c2"
    $a1="cf438659125ea1c48ac48d96977cb371c6b81434247cf2aff89d6d0b2be5033c"
    $a2="66331a930574620b03aa9936ad5b07db7e90d653c8d5fca2fc6e1480fc1c721f"
    $a3="cf438659125ea1c48ac48d96977cb371c6b81434247cf2aff89d6d0b2be5033c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}