rule sha1_hashed_default_creds_stulz_gmbh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stulz_gmbh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7e96ffee48110371dfcdf4af8778be2fa2ae521"
    $a1="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a2="e9d442b26489be9503b393cbe1b8bb7b27e18f20"
    $a3="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
    $a4="dec7dc552bd2ad31c72578b8a5d1e8c7a31635db"
    $a5="1eda23758be9e36e5e0d2a6a87de584aaca0193f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}