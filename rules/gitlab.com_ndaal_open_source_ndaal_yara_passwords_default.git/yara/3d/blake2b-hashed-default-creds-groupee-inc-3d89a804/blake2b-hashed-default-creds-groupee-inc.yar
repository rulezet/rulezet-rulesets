rule blake2b_hashed_default_creds_groupee_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for groupee_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d504d6aa3f0eca36bcaedebedc9f0bbfa2fba4de93fb9d4d6398719cb26797bf27d3abcfc3784db32030e040e1cece7d0d3fd3ed2796bb4651293584db4b8fd2"
    $a1="2da66a5a9b5134c7239c12e0b783c54eaaa343592cbefe13d8591baee600f072ddf2be2f6bbe8089e6b81427df48f5b7c95c68df3f4e81dc68fa23fe5fb365c2"
condition:
    ($a0 and $a1)
}