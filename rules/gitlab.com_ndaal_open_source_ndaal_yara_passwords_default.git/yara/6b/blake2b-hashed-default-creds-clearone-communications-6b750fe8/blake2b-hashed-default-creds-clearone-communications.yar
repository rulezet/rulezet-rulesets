rule blake2b_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e8b661eccb7755608285d8df90d4b20edce71ccdbe76f9c23cf82fd9e4447202dbc951aadf0b3de93cb3993abc03cc2d0fe183b2c48d568910fb16a28a942ccf"
    $a1="200d1408e8e9aae885b9d686c724d45f1f0df4fb28df147279cbe5865ba0590e770f90cdc0be3ca90fb78825940aa56e00449828fe403ba0562fc0e5f08ce3d8"
    $a2="92df82a884b3edbc9f73f48d7558a88f83670bc43faa86f4e7258fbeb3c6e04f4a55023709542c39278a2a2e24827d155cc6a8f3ec7d19ec56eaae85fcad35a9"
    $a3="d4a6a8df325d4f527cc09e3aafa10a97e9017b197ed6fd21a884f6166c0975990d2ecd694ffbc5e7c5d4198a7f76dd972f2eeade71536e1a94a86c73bd067d33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}