rule blake2b_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9bb44cf4c431cfc1a6dbdab87cca99d5ab05b52290f2c8ad8038a083f4a16dff02a5a10b5bcaceae303db40d3bd12977d72865e6172c4850536a11233fccaa93"
    $a1="9bb44cf4c431cfc1a6dbdab87cca99d5ab05b52290f2c8ad8038a083f4a16dff02a5a10b5bcaceae303db40d3bd12977d72865e6172c4850536a11233fccaa93"
    $a2="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a3="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a4="d6fd18c9016526b943d45581ab14652513a935263fdd148a4de8361f08f890ff6f13f65d2983875a0f76c352bfa9c09128d2632e5b137f184d50e9ab948f7e22"
    $a5="d6fd18c9016526b943d45581ab14652513a935263fdd148a4de8361f08f890ff6f13f65d2983875a0f76c352bfa9c09128d2632e5b137f184d50e9ab948f7e22"
    $a6="cfb4b045634bdeaa2fccc366e9e7fac7ceb2bcfc2a19e6c8ffd6c3f49736d91c2acc6e0911365ae6bf30c3a4aeb2f47dd1ba9356ae2887b9bbf2ddee9640711c"
    $a7="cfb4b045634bdeaa2fccc366e9e7fac7ceb2bcfc2a19e6c8ffd6c3f49736d91c2acc6e0911365ae6bf30c3a4aeb2f47dd1ba9356ae2887b9bbf2ddee9640711c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}