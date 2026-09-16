rule sha3_512_hashed_default_creds_electro_industries_gaugetech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for electro_industries_gaugetech."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a1="40bd2966cd3cbaa13a0a32a668619531d52702e98c298513f81fe205b941a45fc3515ed296ef55a67808a85d7289430dc79a11c71d23ce0613a2f7e5032e0b9c"
    $a2="413ffc3aa5a750b22f6a12418b129737b348da7dc59e6c6fb4a3d86ca5a3e5b3673699fce1c0abb517e4016951ec079c79193a5389079bc99094a71caebc9cae"
    $a3="1b1c71435457ee2b9c39e6956b49efe161527aeadc173e609b8604d0d1f8681c84ff664305e8b6961ec77962807e34fae71daab3ee0367444a3e5216423172f2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}