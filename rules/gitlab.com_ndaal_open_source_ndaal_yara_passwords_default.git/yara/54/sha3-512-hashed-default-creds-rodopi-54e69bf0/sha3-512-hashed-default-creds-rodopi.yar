rule sha3_512_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5240ff6be65ec77463d5120cdfd9105ab0ec9c24a133a1c06c28d0266a4cf017c9d50806c57c7a71a00a2f345462be265d6c166d4b951c5ba8f6878912f1c7c3"
    $a1="5240ff6be65ec77463d5120cdfd9105ab0ec9c24a133a1c06c28d0266a4cf017c9d50806c57c7a71a00a2f345462be265d6c166d4b951c5ba8f6878912f1c7c3"
    $a2="c4588c2083bf49a593c9d78ac02db0191fb9cefc9eee6ad2fbd5fd42456b8949b95968208069d9006e2f62d2957d51ac66e6b058172f652d0e86c70f50065872"
    $a3="c4588c2083bf49a593c9d78ac02db0191fb9cefc9eee6ad2fbd5fd42456b8949b95968208069d9006e2f62d2957d51ac66e6b058172f652d0e86c70f50065872"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}