rule ldap_sha1_hashed_default_creds_draytek
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for draytek."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a3="{SHA}WWFgGLMbeWVXb10DNA+XsBBuh6E="
    $a4="{SHA}cRDtpNCeBiql5KOQsKVyrA0sAiA="
    $a5="{SHA}4A7zUaVFL2M+UHF4LNVQvAr7RNs="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}