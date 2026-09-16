rule sha3_512_hashed_default_creds_alien_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for alien_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b914c3a3a0151124915c32df54a911748f0645ed7328bb4f2c0b5daa4617662a72241858ccc29ddb0bfe9624f8d91522b2f423d3f9586eaa3f6365a6c3d4c24"
    $a1="7b914c3a3a0151124915c32df54a911748f0645ed7328bb4f2c0b5daa4617662a72241858ccc29ddb0bfe9624f8d91522b2f423d3f9586eaa3f6365a6c3d4c24"
    $a2="7b914c3a3a0151124915c32df54a911748f0645ed7328bb4f2c0b5daa4617662a72241858ccc29ddb0bfe9624f8d91522b2f423d3f9586eaa3f6365a6c3d4c24"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}