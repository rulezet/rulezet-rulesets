rule sha384_hashed_default_creds_pentasafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pentasafe."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e67384b0ddcd5d516cc517620d5a4dc2442625c7e42ca906497618256c42ab1fd2a2dc4e3cfdaf7e5f9f610994275528"
    $a1="0784ddfbc58bcf94b03148c9d1bc3464b127130496e7cf2a9bd3b14dbc9bcf7337970b58299611b81575398a922d8a3f"
condition:
    ($a0 and $a1)
}