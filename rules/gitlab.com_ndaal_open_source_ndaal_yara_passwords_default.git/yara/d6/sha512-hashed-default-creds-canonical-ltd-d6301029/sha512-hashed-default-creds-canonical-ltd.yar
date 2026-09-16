rule sha512_hashed_default_creds_canonical_ltd
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for canonical_ltd."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ec3759e2c570d302e65ea20a7d985e3bc131024889ad902a046c385afcd71beec61a4f2a5e4ce56863f54840b7315d692cfaeda8239481e37b00cade86139abd"
    $a1="ec3759e2c570d302e65ea20a7d985e3bc131024889ad902a046c385afcd71beec61a4f2a5e4ce56863f54840b7315d692cfaeda8239481e37b00cade86139abd"
condition:
    ($a0 and $a1)
}