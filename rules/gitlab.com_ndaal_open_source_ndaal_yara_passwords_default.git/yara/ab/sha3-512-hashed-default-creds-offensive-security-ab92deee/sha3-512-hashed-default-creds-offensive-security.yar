rule sha3_512_hashed_default_creds_offensive_security
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for offensive_security."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17bbd4bd5bcf969ab5874e84d389d9d28f511529c08fd55f6f733f3a43a9609759e6c955ef7211751fb40ea61292b289c424638801b00b223589e49b14d27a1b"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="73efab342d5db69356a6f29739897ca187580b6ce27eda2ea4996a6d4decb4709ea167d9d18e53976c50fe2da1a8c39fc12b36a842b923c9289e059a3cf4b972"
    $a3="73efab342d5db69356a6f29739897ca187580b6ce27eda2ea4996a6d4decb4709ea167d9d18e53976c50fe2da1a8c39fc12b36a842b923c9289e059a3cf4b972"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}