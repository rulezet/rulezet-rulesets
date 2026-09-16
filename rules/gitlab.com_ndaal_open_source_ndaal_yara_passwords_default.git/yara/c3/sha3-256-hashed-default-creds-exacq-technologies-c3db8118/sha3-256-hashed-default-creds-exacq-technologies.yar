rule sha3_256_hashed_default_creds_exacq_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exacq_technologies."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a4d77792583e8d590eff7f826fa1f7179cf34c331f688209aafd14448edb982"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="266ca12b72242c6ae68431e0003a997b34c4e5e0eb1c3b5eb29549ea6e539c03"
    $a3="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}