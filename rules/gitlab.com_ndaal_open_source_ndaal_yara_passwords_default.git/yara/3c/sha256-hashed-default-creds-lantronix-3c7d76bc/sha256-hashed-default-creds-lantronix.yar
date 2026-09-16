rule sha256_hashed_default_creds_lantronix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for lantronix."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bbc5e661e106c6dcd8dc6dd186454c2fcba3c710fb4d8e71a60c93eaf077f073"
    $a1="d6a7cd2a7371b1a15d543196979ff74fdb027023ebf187d5d329be11055c77fd"
    $a2="2f9acb02faa121bb2a3621951f57b4c690655337edee2e5ac350be2b3be88ea8"
    $a3="d577adc54e95f42f15de2e7c134669888b7d6fb74df97bd62cb4f5b73c281db4"
    $a4="a0561fd649cdb6baa784055f051bad796ea0afef17fca38219549deeba4e8c1a"
    $a5="428821350e9691491f616b754cd8315fb86d797ab35d843479e732ef90665324"
    $a6="2f9acb02faa121bb2a3621951f57b4c690655337edee2e5ac350be2b3be88ea8"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}