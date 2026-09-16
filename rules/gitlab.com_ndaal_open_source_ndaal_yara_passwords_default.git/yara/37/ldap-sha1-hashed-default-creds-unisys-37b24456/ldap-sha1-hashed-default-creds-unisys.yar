rule ldap_sha1_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}JcXRhP08jn0krw4jfAYfVICl6G4="
    $a1="{SHA}JcXRhP08jn0krw4jfAYfVICl6G4="
    $a2="{SHA}9Asn1ri5pPw4JyZMHaFqBOz00JQ="
    $a3="{SHA}9Asn1ri5pPw4JyZMHaFqBOz00JQ="
    $a4="{SHA}N9yT3zuKPaA35CzQy2MjUrNldO8="
    $a5="{SHA}N9yT3zuKPaA35CzQy2MjUrNldO8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}