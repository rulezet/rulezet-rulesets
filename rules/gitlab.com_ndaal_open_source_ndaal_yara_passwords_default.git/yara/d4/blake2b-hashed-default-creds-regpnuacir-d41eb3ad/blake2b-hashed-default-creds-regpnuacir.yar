rule blake2b_hashed_default_creds_regpnuacir
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for regpnuacir."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40d092076d9173a0d632b4ba20427d832009da5a8edcf65e080f4b790f2466ddd558d2b5a700bbbeec052de30c551bb40bf289c6697d89a091da477df7583ccc"
    $a1="8b5d353b7f1f8f96d3ada7a56b92b25d7d98c9e807a802ec537e1f144d3a144fdf088caf039a21d2eca78edcf68b662b1d8d9aef80fec918e458151753dce9d5"
condition:
    ($a0 and $a1)
}