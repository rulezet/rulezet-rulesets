rule sha3_256_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="589e39f67c3fb3ad3292b34e1928ff402264934ef93f9845f17179276148a1eb"
    $a1="1f1df6fe9ce32d33df425136ae7bcd1240ae631fd0dd77cb3c834ee91b7895af"
    $a2="e2f80d07553f0988663d789843f37132cd19f4ef2555b00cfd2378457ab35014"
    $a3="e2f80d07553f0988663d789843f37132cd19f4ef2555b00cfd2378457ab35014"
    $a4="a378307f71cb1d8b9c1a3a8c1f49cc7d33ab33d27cfd4ad10f07acd8ee720464"
    $a5="a378307f71cb1d8b9c1a3a8c1f49cc7d33ab33d27cfd4ad10f07acd8ee720464"
    $a6="3e1f6036a07308c385e0c7f0137ef9f8b686609f4a0898c3d0039608f059edc6"
    $a7="3e1f6036a07308c385e0c7f0137ef9f8b686609f4a0898c3d0039608f059edc6"
    $a8="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a9="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a10="f7e9a4050f2a4abddc406b4acaf0403eb7d11f002298c90859adc2e58e7c4ae2"
    $a11="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a12="0cf8252befc33ca56dce45342f5978d47b8eef41180ead2ae4e977edf411b208"
    $a13="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
    $a14="0d809e4c5b7618f9c64971243fd7632724545c9acda1b89f24d519ea8ddeaa58"
    $a15="602c5b4500e293fcf6497239f327fb215abcfa7d4a69baa1d7e547e582e65bf8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}