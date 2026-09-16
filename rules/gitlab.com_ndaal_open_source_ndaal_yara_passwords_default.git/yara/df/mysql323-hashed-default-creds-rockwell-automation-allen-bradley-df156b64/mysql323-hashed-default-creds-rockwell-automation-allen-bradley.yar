rule mysql323_hashed_default_creds_rockwell_automation___allen_bradley
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rockwell_automation___allen_bradley."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="58f7ee435f925abe"
    $a2="5d2e19393cc5ef67"
    $a3="43e9a4ab75570f5b"
    $a4="14cc52d0761ecf63"
    $a5="41bf12fa0c1dc5a2"
    $a6="14cc52d0761ecf63"
    $a7="3e643a40542063b2"
    $a8="57510426775c5b0f"
    $a9="57510426775c5b0f"
    $a10="3d6a18240601ebdb"
    $a11="7a7eeba37575fe5e"
    $a12="30f0cbc11bc9b6d2"
    $a13="7a7eeba37575fe5e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}