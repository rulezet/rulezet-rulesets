rule sha3_512_hashed_default_creds_ftp_ftp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ftp_ftp."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8a0bdb3959e47ca7ddac9de50e22d980cfdbfda8717f40ee66ddb75835a64fe90a120e940c102e7d28ddf723d10da2cd11218121051756ce234b63671a455ad4"
    $a1="8a0bdb3959e47ca7ddac9de50e22d980cfdbfda8717f40ee66ddb75835a64fe90a120e940c102e7d28ddf723d10da2cd11218121051756ce234b63671a455ad4"
    $a2="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
    $a3="6a5bfbd98d1312047dc685888dc1fde0f998092f97068f484e7ba73032c604652aee25ad2c8dc6774c8a1d718d1e623b7b79390fcc5edd1c7802fbd793d7d6af"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}