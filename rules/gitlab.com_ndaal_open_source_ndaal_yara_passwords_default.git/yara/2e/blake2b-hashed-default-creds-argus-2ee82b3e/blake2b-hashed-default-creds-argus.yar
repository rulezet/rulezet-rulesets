rule blake2b_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95634d08635b26a78df2c5dc103556cc1a15ca5858c8bda7e04b16f9e68a8644eff5d2508be346a0c3ce742f064aa9abcc65e60302b589ecf88178ebcf9bd9ab"
    $a1="b8f9e0df0ffa0732974eb4d904e6ba3d3a9588fbf0bb65d5db3c057087e1408f760c4acb326da95ed56a8ee0c510fda49cd58b6f9f325b8832323d2006a2843e"
    $a2="0293a48f83a256d0cf9a961c1f4aec452b82a135c93b3761f69e1ee3004e9bfc4235c754c68396e42bca688d3fb1f288005892d049c912b3cabaa6ab33ec3e95"
    $a3="0293a48f83a256d0cf9a961c1f4aec452b82a135c93b3761f69e1ee3004e9bfc4235c754c68396e42bca688d3fb1f288005892d049c912b3cabaa6ab33ec3e95"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}