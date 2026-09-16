rule sha3_384_hashed_default_creds_stuccoboy
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stuccoboy."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="29ffe8dfc4f2e79ef5f64abac8123a0a37c5dbe5104f986f56f2bf191041c49501b8fad99a32c692a3e2addfa03c2aac"
    $a1="ac9367d2f40609bace83c499e928ebbaeacbef76bc2e5ae5e81cd25b79966ac36fc47ebc0aac4f28c6f1d9c1b0320db7"
condition:
    ($a0 and $a1)
}