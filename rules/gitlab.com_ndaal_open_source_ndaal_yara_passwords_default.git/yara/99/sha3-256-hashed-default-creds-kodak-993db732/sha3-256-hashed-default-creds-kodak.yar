rule sha3_256_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e0c5cdd254e2ec0fa82a184a704747a84b961ba2c8e65c8ecc9b73dce054f20"
    $a1="ee2db87d7e41822d79cf016a0d92f4cbf15b5fb194b4e0f3e33410d67017ca50"
    $a2="8e0c5cdd254e2ec0fa82a184a704747a84b961ba2c8e65c8ecc9b73dce054f20"
    $a3="7da749a8870dd4a3d62904108edbe42f9c96ff293911dc6c38afc7b1f4f8c836"
    $a4="8e0c5cdd254e2ec0fa82a184a704747a84b961ba2c8e65c8ecc9b73dce054f20"
    $a5="4f24fd3ceb02c63c6fdff3b7fff921bd17240479fb0aec632c63d123eeaf8d55"
    $a6="edad46f180bc906586f1a2635f97c126a68e198a5c990c3bb62d5c5208ac91a1"
    $a7="0cbde9a2c19b092dbaf72e1f40c534ca2e82e3a6c76e89991d78b03541a0e15c"
    $a8="91bc7765fde5a1b73d63c9bc9d9ccdec515c2f149d297990526996d48e2393ca"
    $a9="91bc7765fde5a1b73d63c9bc9d9ccdec515c2f149d297990526996d48e2393ca"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}