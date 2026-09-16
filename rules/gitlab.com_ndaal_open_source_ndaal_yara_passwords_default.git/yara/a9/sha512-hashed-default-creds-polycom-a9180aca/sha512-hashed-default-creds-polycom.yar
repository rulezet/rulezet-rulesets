rule sha512_hashed_default_creds_polycom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for polycom."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f6b07b6c1340e947b861def5f8b092d8ee710826dc56bd175bdc8f3a16b0b8acf853c64786a710dedf9d1524d61e32504e27d60de159af110bc3941490731578"
    $a1="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a2="8c10144fb8485e7056365df293ac9bbb2ac01bed7c7656e2e0315b7beaa878f1c394beedcd9baea3f5bc0544e7a4c3bd60bcd2d418f2ae1a12cccc5d1fe976c5"
    $a3="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a4="46534abbc7b4d4f4a348f43324f861e8e583e9f4c5a4bef73ac7eb9c476df48ef65a8a16fec5031e9eb8f8f5b4e6a8f0ae30f31eec1c6669d5be0d04888605ce"
    $a5="cf835de3d4ea01367c45e412e7a9393a85a4e40af149ed8c3ed6c37c05b67b27813d7ff8072c1035cedd19415adf17128d63186f05f0d656002b0ca1c34f44a0"
    $a6="056a04f5dff1be846d7edeb527d1debd104663e0fddbe1f1d28abda6f4d0869c75284126492617980be9f7aec391937e416833fb8c1e1e7b8a56f2015cd1bd3c"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="c03acaa86255c2ed52831dac7d04546ed150c370f873d624252b81b80ade3b3a85552100cab4771c938217cdb4715655cacfd25628394f54f059fd4669b61196"
    $a9="19c18441d69484b5a944345313844e87ce6462489a096479eac9c6aa4eebce171063e41749a6bf6c303e4fceeb232cf944fd3e606429682e05b74a0c18a6b889"
    $a10="f6b07b6c1340e947b861def5f8b092d8ee710826dc56bd175bdc8f3a16b0b8acf853c64786a710dedf9d1524d61e32504e27d60de159af110bc3941490731578"
    $a11="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}