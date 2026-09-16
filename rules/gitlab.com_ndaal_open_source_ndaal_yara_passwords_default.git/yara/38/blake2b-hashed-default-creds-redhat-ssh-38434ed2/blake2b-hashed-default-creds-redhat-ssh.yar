rule blake2b_hashed_default_creds_redhat_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for redhat_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a3="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
    $a4="d6764cd7f36006d17c9c0de176f578d8ac764c5381daf01d2f8bf23527bcf12d3efb2431f65589f3493ccdd31b4b1467b50559293e2f27d9f0974abd793bee71"
    $a5="7480e09b7bb6f1076f9e81ff613a53e42053ad1a0acfd07883d21f1a98b93d36ec027e452bc7f6d41a02aadec9a376cf61cf245be280e0986a1ca82cbdcfe050"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}