rule blake2b_hashed_default_creds_dotnetnuke_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dotnetnuke_corporation."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecb5d0ac5867af43cd3248351aaf3c9a37a7f43941afb1e2dcd8f06dbf77ef5613d3e0ee9cdcb55a62b058798d16b1a6ddc4a01764a16723e52e83524e3a92ef"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="4bac5cf787ff4972e4736aa7c8cf99ed090f8faf156f7d11dee474c67e829625508673a7ef7706ddb3f978c856bb66a4fd345e5d9dfbe7831ca6fe44ebc3a9a2"
    $a3="e632aa49869df1d3f18924570d119e21d74eba22c223fe2c7a44fda534be1775b16f3f820bf4581e53da8995549822a25295d411a01ef020b71ce79902056a3b"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}