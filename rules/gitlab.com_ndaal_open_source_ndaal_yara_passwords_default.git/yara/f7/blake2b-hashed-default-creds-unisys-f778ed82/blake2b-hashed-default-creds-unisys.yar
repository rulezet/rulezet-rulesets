rule blake2b_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2fcc7f0fb746f5731e2986d3c801ba2f8750cf8ce6c0c94530122dd2ec503b798bc4d1bebec41040242b9b349ab0ac34f2f5ac0320e83b64dffcddf1e97efad4"
    $a1="2fcc7f0fb746f5731e2986d3c801ba2f8750cf8ce6c0c94530122dd2ec503b798bc4d1bebec41040242b9b349ab0ac34f2f5ac0320e83b64dffcddf1e97efad4"
    $a2="142cb3a983c6f7b0586e66f9f8e1f647ad59a143afe6acc09931abce078102cd11a282f23fbda39ded6b784985e2268528628e5ba35ebdc1aead6d04535e3eb4"
    $a3="142cb3a983c6f7b0586e66f9f8e1f647ad59a143afe6acc09931abce078102cd11a282f23fbda39ded6b784985e2268528628e5ba35ebdc1aead6d04535e3eb4"
    $a4="ed147631c18cfef980bed1125cee523643980c5843fa1d8efd954b2ef4fbbf0c3ad0160d02b5fec246d171959aa4e4e7ba6fe65dbe88283a806c2131411d9a21"
    $a5="ed147631c18cfef980bed1125cee523643980c5843fa1d8efd954b2ef4fbbf0c3ad0160d02b5fec246d171959aa4e4e7ba6fe65dbe88283a806c2131411d9a21"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}