rule blake2b_hashed_default_creds_jasperreports_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jasperreports_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="00de78040cc8520f9a7290ec4f00e9436de01dc310dc6db4fc9e8c65d56c073a5c2f07fe07d168590cfcf3f0b739086b5bc5829e2d8d31af109697ad7d2b02d8"
    $a1="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a2="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a3="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}