rule sha384_hashed_default_creds_bewan
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bewan."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b00841609ae946c03a7df6b0093076ac3edaef95252a2b9efe3be73d0c356a1269e251cfe968160eee633bad581eba18"
    $a1="b00841609ae946c03a7df6b0093076ac3edaef95252a2b9efe3be73d0c356a1269e251cfe968160eee633bad581eba18"
condition:
    ($a0 and $a1)
}