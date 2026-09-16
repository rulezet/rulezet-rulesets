rule sha512_hashed_default_creds_borland_inprise
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for borland_inprise."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5f92dcae90ec87247840df8a76a195aa1cd0f7fe996b1d79eb6f9da2294338a556b46cfd64e0fe3a00b71952e17a72880b01540485924150fbb5448098e6853"
    $a1="baefcd6c04eb788b2119ba9a1b6ee55bd9e0f872d2deb8eeef9723810f789774b2bf20e1d0d05d094e4b62a7b1062cc9e5c646128359ffecdd7b912eb1c38bdb"
condition:
    ($a0 and $a1)
}