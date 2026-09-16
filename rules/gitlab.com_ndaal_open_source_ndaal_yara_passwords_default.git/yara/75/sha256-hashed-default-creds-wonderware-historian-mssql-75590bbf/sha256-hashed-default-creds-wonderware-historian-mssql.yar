rule sha256_hashed_default_creds_wonderware_historian_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wonderware_historian_mssql."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47795cf8a5bab85fdedbf59fe1fd0666f91d3debd678d65855a4648e4ac2bd47"
    $a1="304f5570bb8880141c743d863ce9305fe2b73da60e13a270203e8f87cf9116d8"
    $a2="cd8a927d23e14be7c437d984d32aa10136de8bc62cab864e592179731459d1b7"
    $a3="afe9fb4f15084c8a4dc6ae159ccd5e7815f9b2cd6abf9b3dc4d26944124fc3ae"
    $a4="a9dbfc5ca2ce76300ee508d4c435bbbd1ed876044b403601a744183bdee9c242"
    $a5="6c9f53a141ba564aee5da913fddcf10f9d7563eb5c4275eada8dba67cef57bd5"
    $a6="3489cf442b78530bebdf7759763c03b833523ecc671068f435f2ac1bd008c7b5"
    $a7="97db57936ca2f82fad9c8bce485bb06bfd2b4edfe4bd8de50a3ea2ec0452d9e2"
    $a8="c92187d4f3cbe43aa7a7e35365a0b3f471eb64dd86b917dc46698fd552363dc1"
    $a9="c92187d4f3cbe43aa7a7e35365a0b3f471eb64dd86b917dc46698fd552363dc1"
    $a10="a89d8073c999553ccb80f1f3eff81358c2c47a2645e32947aec9769cc0983b0c"
    $a11="a89d8073c999553ccb80f1f3eff81358c2c47a2645e32947aec9769cc0983b0c"
    $a12="1c644aada850130e568f31e646f78ef65c3408b77f67bbe676f7516ebee599e1"
    $a13="1c644aada850130e568f31e646f78ef65c3408b77f67bbe676f7516ebee599e1"
    $a14="37c40d18a79eddabbafdecd7e79cb5fbda5af5be7a30cf3c5e124a325711050b"
    $a15="37c40d18a79eddabbafdecd7e79cb5fbda5af5be7a30cf3c5e124a325711050b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}