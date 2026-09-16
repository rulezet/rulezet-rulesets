rule sha1_hashed_default_creds_saf_tehnika
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for saf_tehnika."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82057a39718ef5802f9e203600d69903a596e6a7"
    $a1="b3aca92c793ee0e9b1a9b0a5f5fc044e05140df3"
    $a2="e0c594e66a94853423e5c83e70a0d0fb09d9cb51"
    $a3="e068514ab6ec7f27907eda03824943109b68d98b"
    $a4="9796809f7dae482d3123c16585f2b60f97407796"
    $a5="9796809f7dae482d3123c16585f2b60f97407796"
    $a6="13eaf6c11377de40d60e2bdb851f3c3b60c1c571"
    $a7="fe96dd39756ac41b74283a9292652d366d73931f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}