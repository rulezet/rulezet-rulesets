rule blake2b_hashed_default_creds_raritan_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for raritan_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="281b1e56e41aec067aaf5e8fe63a06a71d673d45fb5a5f1a86c334fd00b5c136ff7f96e67d1c89e7e952e5f4f8f8b5bc56503ca166fe80746c0a40ab1785e309"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="281b1e56e41aec067aaf5e8fe63a06a71d673d45fb5a5f1a86c334fd00b5c136ff7f96e67d1c89e7e952e5f4f8f8b5bc56503ca166fe80746c0a40ab1785e309"
    $a3="9c93ecfc807036a405c19a47d90313c1557ad1c5da76ec4744fbde445292d4488693462ccc2465501af28406db8ea6922a2257f6e5c0a14b6cfa39cafaef8feb"
    $a4="028b2f6a7c2584fe1541d4b14fe089bfea7813546753b81451dcd03bf0df8e2e00309c539bd357f5b1e67b963388d0c3662f23232e8945e1a55d6c87b8eca2ae"
    $a5="38db7ea89709383c6a76ab6c282bcb0d0aaec8be35a1f3842fb78e9081f7b4c1b34e3ea123286030575eab30004b10675a987660ff66d757b91a88b0ab292aa3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}