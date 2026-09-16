rule sha384_hashed_default_creds_tsunami
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tsunami."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f8088cce58d09184bfc1fd3e950454ef4918d5360724ba6cf608df77ff182aaac15b6e83990b04f139fc76264b1e2bda"
    $a1="f8088cce58d09184bfc1fd3e950454ef4918d5360724ba6cf608df77ff182aaac15b6e83990b04f139fc76264b1e2bda"
condition:
    ($a0 and $a1)
}