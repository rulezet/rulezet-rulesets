rule sha384_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e159e949a4c01fd850b4692b2737df2f3a91e6bc3dda025a30b37eb0e8140cdd6e94b4819bc054f19ebf14f1606e0733"
    $a1="33d44ddc66107dd995f7f2699667933b9412f67e4ea6adaa58386bb10e39d479ecdbf37bcf0610d5fb7d9a394b051a57"
condition:
    ($a0 and $a1)
}