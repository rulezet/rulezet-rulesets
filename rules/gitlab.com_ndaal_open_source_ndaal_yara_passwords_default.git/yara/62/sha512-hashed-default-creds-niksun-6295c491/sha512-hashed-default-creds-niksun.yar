rule sha512_hashed_default_creds_niksun
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for niksun."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4c881366d51b5135df67ba20ae7b74db83d3528ba850fdc2769367cfa14d4019b3599f643828897f554f0615a4f819ea73291facfa1a414affe6444ddf290bc"
    $a1="12e0b4e14f49444ee4f3b58ccfc0fdbcd16a9d74e272e23b24ee8d956bda5fa751f3ad77cf23ee18f3254774156d40ea1cc3e580243b23c2efc94571e65719a5"
condition:
    ($a0 and $a1)
}