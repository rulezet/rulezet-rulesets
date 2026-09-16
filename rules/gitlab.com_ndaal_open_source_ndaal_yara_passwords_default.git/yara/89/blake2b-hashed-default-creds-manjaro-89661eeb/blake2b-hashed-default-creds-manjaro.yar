rule blake2b_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc8c46e2fe0f14db91eb6215e9de1143d4cb8d4ab67b5f877e3528998caaa55ea3b746523408942c9b3b9cc6b9520d76025f061a5d6dbf82f94456d84a245172"
    $a1="18063aed84a0d6785ebbc098f5a9f8a24297be6502acdd901df5ba96705d07532856c22fa870a88ac30f8d6f885241ca3790b6e87d4c3b639d082ff598da3093"
    $a2="40a5c6a46c0d33f0303777b2ab597e61136c1303b6b71830b76bc11442d9e30f647ebfa1128e3ddeab10d60db997f1a266caa3d9dc63ab159bee60adce8d6269"
    $a3="18063aed84a0d6785ebbc098f5a9f8a24297be6502acdd901df5ba96705d07532856c22fa870a88ac30f8d6f885241ca3790b6e87d4c3b639d082ff598da3093"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}