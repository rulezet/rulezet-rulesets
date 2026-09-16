rule sha256_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6a6cb14af365591a498c456589b151e4d1b174ee90da0cd94b96a7ad7dd9b8c"
    $a1="598e519219f23461b638164fede36f184a05c88d1ef2a40678d79540a4604cf2"
    $a2="c6a6cb14af365591a498c456589b151e4d1b174ee90da0cd94b96a7ad7dd9b8c"
    $a3="dc9cac60f7626286cbb9bfdfbe3c4aaca67f40e63f384a41f6f02133c7e39e45"
    $a4="c6a6cb14af365591a498c456589b151e4d1b174ee90da0cd94b96a7ad7dd9b8c"
    $a5="04b7621748c79505370721bd391337188a01d04cc0212759f250eea466a59816"
    $a6="0be64ae89ddd24e225434de95d501711339baeee18f009ba9b4369af27d30d60"
    $a7="360bf3a8254ab93fc69e84ce6640d78535a34f3cdc0b1bdacec6ccdd93726a79"
    $a8="d677190e0a9990e7d5fa9e4c1bbde44271fb8959c4acb6d43e02ed991128b4bf"
    $a9="d677190e0a9990e7d5fa9e4c1bbde44271fb8959c4acb6d43e02ed991128b4bf"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}