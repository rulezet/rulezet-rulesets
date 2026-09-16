rule sha512_hashed_default_creds_cyclades
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for cyclades."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17df8638c5eb822838ccf6422384dcf31f9f148ada3e829a7d805f37778ffaa3bd22e4caa842187cd04dad58e90c70fb21b8a8bd459c1506d3968e1f0207eb12"
    $a1="36379d8584770820d95741c8efe571cc0ab37e2021c505fd8f384724d0676020ebc6d4f318e2533acf708fab8ede09c950a8daef54299ab9ea5ba1e1fd4b73bf"
    $a2="881f3366b243fc862e4abde906658fcb812122eed2c27a7e864890a9c11fc3e9da88a7351d617ba80c88e06861202ea7bfdb19438e8d67807f610e4df466d628"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}