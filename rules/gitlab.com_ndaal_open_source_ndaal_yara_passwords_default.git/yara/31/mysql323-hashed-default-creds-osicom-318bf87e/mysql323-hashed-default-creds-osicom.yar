rule mysql323_hashed_default_creds_osicom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for osicom."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4701175b460f3f84"
    $a1="4701175b460f3f84"
    $a2="4660c1d55c384af6"
    $a3="4829c53d6f9319a1"
    $a4="57510426775c5b0f"
    $a5="57510426775c5b0f"
    $a6="4077eb0b03ddce3b"
    $a7="2ac90b9577c33931"
    $a8="15f73cd91718b388"
    $a9="4660c1d55c384af6"
    $a10="15f73cd91718b388"
    $a11="5f1c284521aa2d43"
    $a12="15f73cd91718b388"
    $a13="57510426775c5b0f"
    $a14="4077eb0b03ddce3b"
    $a15="4701175b460f3f84"
    $a16="2ac90b9577c33931"
    $a17="2ac90b9577c33931"
    $a18="5f1c284521aa2d43"
    $a19="5f1c284521aa2d43"
    $a20="29d7619622ecb839"
    $a21="462bb13c0e48d7be"
    $a22="558bb3e11f999dd8"
    $a23="04964711571d0a96"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17) or ($a18 and $a19) or ($a20 and $a21) or ($a22 and $a23)
}