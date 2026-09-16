rule sha384_hashed_default_creds_aris_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for aris_mssql."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8da2e51fde9d47294d76ed066f16d43f4c698cd5675f6ba39a5351e46e3748c4fb02c6625fd87cf7c92a3deb7c39dacd"
    $a1="fa28e61969da6e2494626ef23f027def7420c27677afe91c5b9eabd3bdf5fe33c97c1de66cb6ad2d3584f111f3d43b21"
condition:
    ($a0 and $a1)
}