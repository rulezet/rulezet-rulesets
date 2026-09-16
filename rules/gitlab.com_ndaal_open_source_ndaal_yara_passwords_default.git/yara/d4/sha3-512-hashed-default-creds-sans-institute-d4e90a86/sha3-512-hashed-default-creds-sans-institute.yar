rule sha3_512_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c328185c10a15933f0f945703008a6faa123785ba8afb4fdeb0eb5305efad930673f0320cc9f6faaccfed74ff29e739bb07d75989439b5ce4f600bec653aea33"
    $a1="9ad45b0fdc9947153215a3a0f2edbf9246b41c44ba83125c149a2bd25b16e94ffa6bbe718ea10631723868db11c47d7059745306ec062b3360d9e98f39653a94"
condition:
    ($a0 and $a1)
}