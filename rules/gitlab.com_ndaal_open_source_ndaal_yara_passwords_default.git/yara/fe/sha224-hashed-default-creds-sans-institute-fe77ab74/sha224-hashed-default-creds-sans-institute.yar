rule sha224_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b90c6d06f6b0f1ae25e5c4d260cc5445afe04fb8b24e5a2b7e1d39c"
    $a1="8324ffa4be68b833ba9ed6765d834f7a9daf0070c52812bcbef0ab70"
condition:
    ($a0 and $a1)
}