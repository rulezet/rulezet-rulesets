rule sha512_hashed_default_creds_tasman
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tasman."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7301a7a91ffc67747442b844f75e39145d312425b48ef51cb0d2869a38e372a4ff67c4ead2f50a34e5fdd261c99756e8df74540f996032762dfe9a81c5d93bcd"
    $a1="af2fb2cbe8abcdf00434ef435c03d638750f5842c1c97c870db9ad7bd9cdb2640715e99df233045618684ce6a3eb1f968822436c2c65ea2dd91a2e11c65916af"
condition:
    ($a0 and $a1)
}