rule blake2b_hashed_default_creds_schlage_sms_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schlage_sms_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61399950475579b5b2441312e3506af9de933917c42dd432c5a145eb5cf32ca7b9e6f6eccd34ba8cf501cce9926d7dfbb73094fc6afaadd5dd7f4ae63858905c"
    $a1="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a2="61399950475579b5b2441312e3506af9de933917c42dd432c5a145eb5cf32ca7b9e6f6eccd34ba8cf501cce9926d7dfbb73094fc6afaadd5dd7f4ae63858905c"
    $a3="16d2d1ca296c5929e0f1129225cee04ced9671246a688e30fb0c8822ffcc4e594aa33630a80ff1c87d5d58d492c7730bf36190e21628c1e20400b095fdebce4b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}