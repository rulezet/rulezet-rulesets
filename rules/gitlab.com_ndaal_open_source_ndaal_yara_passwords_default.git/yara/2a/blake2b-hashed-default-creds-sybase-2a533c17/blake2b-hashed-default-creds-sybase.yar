rule blake2b_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2e61c67977e90d04fc2ba0130a3a1ece4b4509afdfa9e58ad706382cc2ec1a94b64d014fce3c06f193bd983afbd2247034627d6c064762b30b983a52e7a4945a"
    $a1="2a4e20a06c9af62af6ea2eb6b070193672690016d0554d0479f0ffc0fd277bedf257618320e3c7af3d8bea6e0cd5d554c9c6bca7c7e05fa09b0bdf7f6cc72d90"
    $a2="8187cf141f305d411400cdcea12f9f947260cdf5e342a8cd2a31386b2bf30a4d4dcb96874a528ef7d010a3e9ba4f0f1e95d7b6e81d967a6c4d763dbf36d7e11e"
    $a3="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}