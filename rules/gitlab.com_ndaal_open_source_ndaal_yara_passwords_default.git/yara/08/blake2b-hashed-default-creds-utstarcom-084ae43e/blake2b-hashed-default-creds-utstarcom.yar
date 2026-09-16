rule blake2b_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfdd66d53c299fa19c480d084569dc3f7a8b5a023cea3686aa765760079aaee96e26082b48b5acf73646947942eddc13502b898ba74b27251ae0490a77c38def"
    $a1="bfdd66d53c299fa19c480d084569dc3f7a8b5a023cea3686aa765760079aaee96e26082b48b5acf73646947942eddc13502b898ba74b27251ae0490a77c38def"
    $a2="8b50d730c745edd0027afd3b23b52d6dc38d8841da714faf5033cd2446d19971b2943a6b3f407926fa3321296759cdce1dd31182189f1e6e481664498dad72c8"
    $a3="6877cbbd9a178b68edeb40f13fa0cb6d00d6e922a12f6da5831f0e2bbe00045c0296a89ddde0d1794481344e21570d9cb86bd64db920635bc880a0cecb7c6b9f"
    $a4="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a5="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a6="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
    $a7="c9364aa9e1e42c37b427dafac704d1a803c60e8d9fd433dd9b69248c25192b4b586a7f8723adf572dbccb308f4c60d433c7ec4a093ade50412ee180c7a7182b7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}