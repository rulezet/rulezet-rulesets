rule sha1_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a07ef5ebc409e10540a4f4a572d31493126bc149"
    $a1="0a92fab3230134cca6eadd9898325b9b2ae67998"
    $a2="c5fe0200d1c7a5139bd18fd22268c4ca8bf45e90"
    $a3="0a92fab3230134cca6eadd9898325b9b2ae67998"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}