rule sha3_512_hashed_default_creds_stratacom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for stratacom."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14f9a0c1b9a35eec9d6c4c6fe4c6def00413c26ba1f0e6b9efcddd51da084b7ee395be21a08dd7259a00ecd6b48abf520fd043d5efcf74ec08db30956c4497a5"
    $a1="bee5381af343c00b4c1747b4e5e64373fe2cbbeb53c6d01adfdab16ca6b5a3ffb1a3297fd7d97877f4b715621d2962188b1e100624482d80fd594f2ee762e108"
condition:
    ($a0 and $a1)
}