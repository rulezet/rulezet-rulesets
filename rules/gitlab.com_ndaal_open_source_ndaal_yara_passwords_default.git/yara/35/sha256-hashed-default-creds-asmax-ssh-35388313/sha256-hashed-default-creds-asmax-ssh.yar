rule sha256_hashed_default_creds_asmax_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asmax_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="a18603086e5bdf9df88ccc9f5a083fed093e819976e87456b74dafcbd7011114"
    $a3="a18603086e5bdf9df88ccc9f5a083fed093e819976e87456b74dafcbd7011114"
    $a4="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a5="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}