rule sha256_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a3="378aa3b3beecc8cd5718f7cec8c60b9bb3042165199648b94e4378c32aa60c89"
    $a4="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a5="061a1c0ea20e6b5d90ace3c0d879304b52c751ef53e62ccf159e1fb21d954c2f"
    $a6="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a7="8bd82fac9d64437eef946dbcec0c0dce185aca62f0f239b5f9a81eb7f53f3eab"
    $a8="9fa444ae546c12aa74b68494378a1e4d08e1674afe0b549cce538f8af36a3e0d"
    $a9="9f4d10730006eef4bf802559e1f26a254ad4eb11b8d0eff66ace8ffb4d1c12bb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}