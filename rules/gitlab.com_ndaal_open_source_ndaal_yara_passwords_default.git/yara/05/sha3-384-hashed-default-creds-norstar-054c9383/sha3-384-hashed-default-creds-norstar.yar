rule sha3_384_hashed_default_creds_norstar
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for norstar."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a324706333efbdf4cc3434918eb0b2bf21b82c0ee7011441529362a2f90ca881b558d9b384fcc4bfbf5b59d503beb48"
    $a1="64fa80ffe97e207d2c8b8f369c04d25d4fad0d2e6265adb99e5146b2d5dd8ef3646cfca838017456ea58fb870a9d2b49"
    $a2="7c7145fd8f72d12a0eb978cd3d7ac867d97dd69f6289cb1ee72d05427101f90ff978d4e799f3874f62e36b4d88afd75a"
    $a3="e7f5a7a49fb75e61ba40141201a09a53aa5f38e91f98a1ac47b357ffd748b69f4ed2ab06c85dac35cc90ef1f3bd1858a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}