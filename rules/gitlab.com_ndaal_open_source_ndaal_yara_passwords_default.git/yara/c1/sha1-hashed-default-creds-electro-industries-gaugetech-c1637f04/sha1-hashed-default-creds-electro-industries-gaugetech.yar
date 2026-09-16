rule sha1_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a1="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a2="db69d6635c3b10934dee6bd7425e87e637f73b33"
    $a3="f79332ecf85d8ba2acd2a1b617c1fc366ed8cacc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}