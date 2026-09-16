rule sha512_hashed_default_creds_honeynet_project
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for honeynet_project."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c9fdcde3a92c52699eaf579fca9d0fc3602852552b67b4d0a9f4a07429835d6f34f375196d73b169d55e313fc3c3e81a2db28779e3a45814704188a40221078"
    $a1="2c0272a79ece6ef78b052cefcd027a98f2c50eb0b8f06774ebd69954922f01d8803d1aec89e03c8982d504dcb7aededb6a8b24afd6359c5605b6f4da4585beda"
    $a2="8c9fdcde3a92c52699eaf579fca9d0fc3602852552b67b4d0a9f4a07429835d6f34f375196d73b169d55e313fc3c3e81a2db28779e3a45814704188a40221078"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}