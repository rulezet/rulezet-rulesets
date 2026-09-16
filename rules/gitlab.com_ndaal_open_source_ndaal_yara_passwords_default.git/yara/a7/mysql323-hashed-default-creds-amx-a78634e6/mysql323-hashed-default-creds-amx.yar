rule mysql323_hashed_default_creds_amx
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for amx."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47233db00d467fa2"
    $a1="43e9a4ab75570f5b"
    $a2="5d2e19393cc5ef67"
    $a3="7a7eeba37575fe5e"
    $a4="3ee702572177881b"
    $a5="67457e226a1a15bd"
    $a6="5d2e19393cc5ef67"
    $a7="05daf8884f15b95d"
    $a8="47233db00d467fa2"
    $a9="4077eb0b03ddce3b"
    $a10="57510426775c5b0f"
    $a11="57510426775c5b0f"
    $a12="43e9a4ab75570f5b"
    $a13="43e9a4ab75570f5b"
    $a14="70ee3358296fac94"
    $a15="58f7ee435f925abe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}