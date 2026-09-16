rule sha3_384_hashed_default_creds_highpoint
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for highpoint."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="55c3d7d0b301593640bd0c4028933ab5d4948d25f73b494185e1cc02c0122c01e9af682ca176fe4beeb7465c89698ec7"
    $a1="c84476727cb63767a3922a16f3e0123cf28778a8a541b686aee768aaaf613e0df2ac572960ca0d74a4a5627fde5110fb"
condition:
    ($a0 and $a1)
}