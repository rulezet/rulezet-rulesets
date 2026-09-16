rule blake2b_hashed_default_creds_tim_schaab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tim_schaab."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae48ad7b8a408c58a6eb311c2c65e4a2b3579078e4e7cb33918b6b0a11dad34a898cf91211ba7718ed483f90c043a19aaaba8d9ca9f3610bad28b63691c9a1f8"
    $a1="bba0b9d3314db0322e75ebfc8cfab750be0a3907637bb6b96539ae716733e36e928383b789da7734f5057f5233c22c6ef75275311e5abe08ad4fb5355081ea19"
condition:
    ($a0 and $a1)
}