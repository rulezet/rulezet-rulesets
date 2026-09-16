rule nthash_hashed_default_creds_citrix_systems_inc
{
    meta:
        id = "7c2O3oti5oQoO7N2KKlFlK"
        fingerprint = "2214c4ec7ad430bd4af93ec7069edd3277210b72c531601b87e34d49ad27300a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6de76e9bc256d0e0fc81247abec81e7"
    $a1="c6de76e9bc256d0e0fc81247abec81e7"
    $a2="824973847639cb5a8ff529dd3f6454ff"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}