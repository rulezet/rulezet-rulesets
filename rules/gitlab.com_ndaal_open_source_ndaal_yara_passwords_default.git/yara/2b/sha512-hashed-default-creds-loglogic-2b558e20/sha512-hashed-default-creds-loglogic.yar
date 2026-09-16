rule sha512_hashed_default_creds_loglogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for loglogic."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3f0b8dd3c30cadcc238fcc20a3fe601eda8203f9f708f1881dbcdcc85b0a9cc94f067c6f4e0ec2b2d8b75509624bcb764b9be677d1337d0d036f9eac4b06e7b5"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="3f0b8dd3c30cadcc238fcc20a3fe601eda8203f9f708f1881dbcdcc85b0a9cc94f067c6f4e0ec2b2d8b75509624bcb764b9be677d1337d0d036f9eac4b06e7b5"
    $a3="2b64f2e3f9fee1942af9ff60d40aa5a719db33b8ba8dd4864bb4f11e25ca2bee00907de32a59429602336cac832c8f2eeff5177cc14c864dd116c8bf6ca5d9a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}