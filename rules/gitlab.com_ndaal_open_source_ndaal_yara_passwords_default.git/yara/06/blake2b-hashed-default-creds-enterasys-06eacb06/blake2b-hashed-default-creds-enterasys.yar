rule blake2b_hashed_default_creds_enterasys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for enterasys."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="97ac4c2a060e714d81767a70edf1b86ed9c8df9c086df538883c26f0598d850e8ffb3ce15d966b5e6f9898c9729c8108c092c9c7577407e5e1a3af940828d15f"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="3c9feacd7a6ef26891503791be4544c98be22ec9271a4134544dd978233495c85604b1efd71352e9187d50aea3c6ad52c701b98be64692519b4dc8921f2b6ab5"
    $a3="1d7e0515bbebf48e479c9e3b70ea9f5c18ad768e6dd6e3d00af372555eadb697219556159edc45a330f585fe5d4220c1330f241666b8500142e8be54f528bf2c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}