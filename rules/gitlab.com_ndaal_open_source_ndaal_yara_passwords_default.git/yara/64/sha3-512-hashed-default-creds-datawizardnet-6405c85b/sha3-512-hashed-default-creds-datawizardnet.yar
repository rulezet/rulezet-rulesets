rule sha3_512_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58b1d2774616992212b71e58dc4e5c4662012d9f40cefd193e3b3cffedd312595c3a7cc4c2fcc6d98a2501bd49f658b3276740455787bfa109a4ea29fe2ddc86"
    $a1="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a2="6b6c2518fc56046954105459797b70438cc08402f8d6eef226fc8f020a2455cf1d82d399252a237846cb6e72215e1168372d99fc54618321ca44838b1705c63b"
    $a3="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}