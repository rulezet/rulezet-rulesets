rule sha3_224_hashed_default_creds_broadlogic
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for broadlogic."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
    $a1="5cd9d36bfd71ccc6cd7ac8d50cc18d3f8f5bdb1a710189d238e1ff09"
    $a2="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
    $a5="6c997153b9824fae73b4f417bb5ee86113c6ac5c8208ad2fe2a11d71"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}