rule sha256_hashed_default_creds_asante
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for asante."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d676e1c20b54d612d398e611b11327d605af6af96464b1bba8a1dfd1de5b55da"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="d676e1c20b54d612d398e611b11327d605af6af96464b1bba8a1dfd1de5b55da"
    $a3="382132701c4733c3402706cfdd3c8fc7f41f80a88dce5428d145259a41c5f12f"
    $a4="33f1a3dac043deb24e70e7b7c5489e7c6240ac64d26e43a1b5785c0efe28440e"
    $a5="bcfe8bf6b05dd55667fb640a0187cc83ac77f436d41467b1bfa7ee782664f56f"
    $a6="33f1a3dac043deb24e70e7b7c5489e7c6240ac64d26e43a1b5785c0efe28440e"
    $a7="a4146dcc6cb08401ffad98d26d3a81d72b93d9a8c6d842e7a9224d157ee7a850"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}