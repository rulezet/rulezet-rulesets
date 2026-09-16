rule sha512_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4e03a8c7e7b54608c1aaa1ac78e4e9bbd7e70466e4ea7e629daa6b0571290dec441a60444f6467bdb51291873708ddb9c1d1ac57a37ef4f920fe17794440d96d"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="bb8e34bc9455c62c8ab10cfa7cbe0d80e9e156f5341a8c9c549e558a17942bf7b900262e29afb24232d4baad598f326caeca95a02ebefba8c5bfd5cf71373c17"
    $a3="bb8e34bc9455c62c8ab10cfa7cbe0d80e9e156f5341a8c9c549e558a17942bf7b900262e29afb24232d4baad598f326caeca95a02ebefba8c5bfd5cf71373c17"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}