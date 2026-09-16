rule ldap_sha1_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}mG2rLK8RuX+78rQ+Ym2+qY51Ss4="
    $a1="{SHA}hcBrhnZ6L9+Rip4wf5Nqs2HNxAo="
    $a2="{SHA}mG2rLK8RuX+78rQ+Ym2+qY51Ss4="
    $a3="{SHA}XpWgW1U2qoIPKOrXpkW6/hMe4NE="
    $a4="{SHA}mG2rLK8RuX+78rQ+Ym2+qY51Ss4="
    $a5="{SHA}bldtS8FikNfxNnFDV0LxoLCYfeg="
    $a6="{SHA}ESu3kTBHkd3PaS4p/VzxSbNf6jc="
    $a7="{SHA}aIyh/y44AOyh6+PPqaA90sOtJ9I="
    $a8="{SHA}Mpy4trqMQnvnwJspgpXGVUFcesk="
    $a9="{SHA}Mpy4trqMQnvnwJspgpXGVUFcesk="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}