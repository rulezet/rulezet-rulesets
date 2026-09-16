rule sha512_hashed_default_creds_davox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for davox."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b87c9bb6db602307da5432a362915b2017e4f27f3871f4e1ebf33a08200614ca42a3808d2c3fe892fe005dcf37498bcfbfff3cc7149c76f28345c7a27a13695d"
    $a3="b87c9bb6db602307da5432a362915b2017e4f27f3871f4e1ebf33a08200614ca42a3808d2c3fe892fe005dcf37498bcfbfff3cc7149c76f28345c7a27a13695d"
    $a4="b87c9bb6db602307da5432a362915b2017e4f27f3871f4e1ebf33a08200614ca42a3808d2c3fe892fe005dcf37498bcfbfff3cc7149c76f28345c7a27a13695d"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}