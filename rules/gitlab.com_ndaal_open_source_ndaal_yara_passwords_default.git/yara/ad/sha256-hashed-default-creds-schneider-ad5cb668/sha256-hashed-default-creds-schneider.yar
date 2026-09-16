rule sha256_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9f8f7a8c040ef2e8fdd133102b65cc526fca99ca84d4c7b67da5951c99977eba"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="5b5f460bcbcda97b60137d28a0d1d089df2ab48a3ffb08d75adad462ce3c9683"
    $a3="e0717cee504531e21a049f6e1f72775c7273ab987e5d2cd4f2ae9a2d59694721"
    $a4="97e991732e1f2034217a50a30031f86a2b3eebc9b33ccae169ffaa2090458a08"
    $a5="fefa82ceb88363173b2f76d214b5b66848087cee1d0b41716d8a53054e48d884"
    $a6="585d081bd4f54e084722ac6c5cd416b1f431ccf5a5fd5deba5e80555f68d0796"
    $a7="982945308d3682d16636fd628c314e293499e99c00120acd9b693f5ab16e1648"
    $a8="7ab18fd7a14d6d731de6eb91fb5bdb2123e705af7fe2442139198f06b7948feb"
    $a9="23a1d40404715c2a6970c6350b01920ec417bdb3f1f6f399ecb3f073542b58eb"
    $a10="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
    $a11="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
    $a12="16ab94f97bde08b9b51910985f9599a63e9514b4e4d29c652d20621de3b8540d"
    $a13="92b7b421992ef490f3b75898ec0e511f1a5c02422819d89719b20362b023ee4f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}