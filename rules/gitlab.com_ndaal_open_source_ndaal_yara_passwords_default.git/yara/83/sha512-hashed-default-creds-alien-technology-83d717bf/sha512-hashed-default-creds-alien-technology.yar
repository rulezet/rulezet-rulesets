rule sha512_hashed_default_creds_alien_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e3d6536c34cc8caddf2b743f8553435c99bcbc6f8e98a814d8a2114f9a04fad9d6c9b4d230a90b9f215e3059b0775e8a8af2c16c92842919b9376e1c3c47b5e4"
    $a1="e3d6536c34cc8caddf2b743f8553435c99bcbc6f8e98a814d8a2114f9a04fad9d6c9b4d230a90b9f215e3059b0775e8a8af2c16c92842919b9376e1c3c47b5e4"
    $a2="e3d6536c34cc8caddf2b743f8553435c99bcbc6f8e98a814d8a2114f9a04fad9d6c9b4d230a90b9f215e3059b0775e8a8af2c16c92842919b9376e1c3c47b5e4"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}