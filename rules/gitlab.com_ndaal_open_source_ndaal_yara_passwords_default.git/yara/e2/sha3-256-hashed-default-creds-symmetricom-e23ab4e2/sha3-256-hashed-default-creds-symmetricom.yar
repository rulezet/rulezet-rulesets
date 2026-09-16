rule sha3_256_hashed_default_creds_symmetricom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for symmetricom."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="884ecd7566533760c1bbc0054a0e279fa37893a90565e098d42ed30542bd8347"
    $a1="79b51d793989974dfb7ea33d388d0016dd93a6e80cdaaac8b34ec2f207c1b70f"
    $a2="88731a9b9f8da70475be597c1d24f4f807b1ae1d901b8d3b802403813c69368e"
    $a3="d238602e3435b266dbc0153b200e85e208a20a0bae71010a6324eb0497804eae"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}