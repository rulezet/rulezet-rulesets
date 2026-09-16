rule sha512_hashed_default_creds_ubiquiti_edgeos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ubiquiti_edgeos_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9a9a1b637cf31e2b159b512c24d3fae2407e2dcf15026c23a19d8828dca4d1b95f32cb78dbd87648afeb9281dee909b37e638e8b971f918579a5e756cafdecb7"
    $a1="9a9a1b637cf31e2b159b512c24d3fae2407e2dcf15026c23a19d8828dca4d1b95f32cb78dbd87648afeb9281dee909b37e638e8b971f918579a5e756cafdecb7"
condition:
    ($a0 and $a1)
}