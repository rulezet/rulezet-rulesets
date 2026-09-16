rule sha512_hashed_default_creds_virtual_programming
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for virtual_programming."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="f86f4f4c3a375e46af380c2b191a35828319b35d1696f370b835edf9a5597bea185aba75f9a6165cbde7c000bbba97531ab686fc9aed3f24e588a74b8160be35"
    $a3="f86f4f4c3a375e46af380c2b191a35828319b35d1696f370b835edf9a5597bea185aba75f9a6165cbde7c000bbba97531ab686fc9aed3f24e588a74b8160be35"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}