rule blake2b_hashed_default_creds_mediaportal_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mediaportal_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2f6e833b82d6840fa3961f9164c286cd0ddbb0352afe74dca815439ae18719516f0c504e2c67fec7ca5b1e9459ef200b565968d61bb8970d674521176d880fa"
    $a1="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1)
}