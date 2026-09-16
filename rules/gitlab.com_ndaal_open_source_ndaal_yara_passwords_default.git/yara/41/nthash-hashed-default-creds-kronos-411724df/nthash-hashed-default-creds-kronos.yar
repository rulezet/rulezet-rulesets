rule nthash_hashed_default_creds_kronos
{
    meta:
        id = "2UAzXmov6Cz8ewMHOQSflF"
        fingerprint = "f0de0cf09032ccea431b0cc1dcd8047b846ff087515749642feb61bbd2180e15"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f0b5267b9b2c6fcafa68f40ed4dad6b"
    $a1="1bb32a778542f2c389aa6c4f90807bf9"
condition:
    ($a0 and $a1)
}