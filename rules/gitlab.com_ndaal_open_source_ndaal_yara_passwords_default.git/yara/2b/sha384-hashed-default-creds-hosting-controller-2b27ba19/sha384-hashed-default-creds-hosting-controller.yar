rule sha384_hashed_default_creds_hosting_controller
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hosting_controller."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ed08b0f0a551a0a8cacd730b9f333baa3524b7ecf31b71daeb0d05ff0aea763fb088eaff3a3249fd96398b6f87af989"
    $a1="495488b92978b8119a98ba215bbcb528d0ca4c017bb4c04a37c31cc21827053c01a5423ab672554445fb8152398090e6"
condition:
    ($a0 and $a1)
}