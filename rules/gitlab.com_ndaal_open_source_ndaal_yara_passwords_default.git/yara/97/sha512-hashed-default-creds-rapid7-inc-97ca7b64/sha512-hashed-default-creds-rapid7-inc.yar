rule sha512_hashed_default_creds_rapid7_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rapid7_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="82a404a489ba70bd23e2cdda1517abb5a830a628ac282781be6ef46e5d32f025f5d083988c4d6375a490beb69daf2c5e7cc27651eb43ce671ff25873650f4eae"
    $a1="82a404a489ba70bd23e2cdda1517abb5a830a628ac282781be6ef46e5d32f025f5d083988c4d6375a490beb69daf2c5e7cc27651eb43ce671ff25873650f4eae"
condition:
    ($a0 and $a1)
}