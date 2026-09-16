rule sha3_256_hashed_default_creds_patton
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for patton."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a1="f873e204d784438609bcb99fbd615e044706cce0c50dfc69ff82b98d9cb8c504"
    $a2="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
    $a3="17ef157db4598ba30e1441a6d807d2bff1d22ca1d0046e7fab619b4d33626501"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}