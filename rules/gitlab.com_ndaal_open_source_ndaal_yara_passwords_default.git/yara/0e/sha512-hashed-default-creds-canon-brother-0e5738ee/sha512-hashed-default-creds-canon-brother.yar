rule sha512_hashed_default_creds_canon_brother
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canon_brother."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a3e8882db900b2665c5fc925bd1ce97d28fe38788f78507c83015c05ead4acad6392ffc3e8b09a469a9769ed682d58cc790be36f64a2ec26d23dcd17dc2f9185"
    $a1="a3e8882db900b2665c5fc925bd1ce97d28fe38788f78507c83015c05ead4acad6392ffc3e8b09a469a9769ed682d58cc790be36f64a2ec26d23dcd17dc2f9185"
condition:
    ($a0 and $a1)
}