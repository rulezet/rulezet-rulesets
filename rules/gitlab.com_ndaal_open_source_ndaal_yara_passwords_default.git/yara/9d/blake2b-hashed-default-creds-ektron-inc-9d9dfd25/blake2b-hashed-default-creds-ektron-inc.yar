rule blake2b_hashed_default_creds_ektron_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ektron_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="34b4bc9a5c5fcef6ebc3cb008eb6e4412ecc131079455ba2ff9d56ff783273a65d2a6001be70bc7cd2d86b3b6c678ec61451fab5021231c7a82d9ff48585bb05"
    $a1="34b4bc9a5c5fcef6ebc3cb008eb6e4412ecc131079455ba2ff9d56ff783273a65d2a6001be70bc7cd2d86b3b6c678ec61451fab5021231c7a82d9ff48585bb05"
    $a2="7d3d4d7e93c044f4a810f47b1d7eb740210d2144b5265d3b37998dc93a8b9d0cdb6ffc154e4cdfd2c36e834533a8739c1a7066f0ad75f598cd178324fcd36e4b"
    $a3="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}