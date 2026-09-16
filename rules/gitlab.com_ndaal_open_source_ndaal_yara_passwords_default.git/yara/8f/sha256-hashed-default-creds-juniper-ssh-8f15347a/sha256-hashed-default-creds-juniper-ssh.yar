rule sha256_hashed_default_creds_juniper_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="b5fec6a11b2236e2c5bd760dd50cfcdba47407dfce613681c05dcd6fb75f7acc"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a7="23bb8b463e0de9b386c62fd5916c01d811a110be4cd2f882c2ab0a920fad19c7"
    $a8="7f411c23e7d9d268b51470b27920d362905e71fca86a2ef5c70747984b30a29a"
    $a9="7f411c23e7d9d268b51470b27920d362905e71fca86a2ef5c70747984b30a29a"
    $a10="0a2b6aed9a29e267b2d2f7898e42316d36a027848755b946c1e9ea42649e69e0"
    $a11="0a2b6aed9a29e267b2d2f7898e42316d36a027848755b946c1e9ea42649e69e0"
    $a12="58dd311734e74638f99c93265713b03c391561c6ce626f8a745d1c7ece7675fa"
    $a13="73d1b1b1bc1dabfb97f216d897b7968e44b06457920f00f2dc6c1ed3be25ad4c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}