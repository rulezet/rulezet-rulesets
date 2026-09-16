rule blake2b_hashed_default_creds_jaspersoft_corporation
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for jaspersoft_corporation."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a1="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a2="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a3="e7f0816836a3094fefa89f962a05b386a6340f740feff1ab6467a67639554aa8820de69c01c9ca342efe45f580dfee1d4da7be30b3686e759c80af9a0a674ab8"
    $a4="aa1c04caaaae639bd37d767ac9022fe6ef7f56c271a4a01996a28aadd4c952d067516f82857bef9574ca77c6818ef4a42cdb6d43ac79fe3b1992864de132ce60"
    $a5="aa1c04caaaae639bd37d767ac9022fe6ef7f56c271a4a01996a28aadd4c952d067516f82857bef9574ca77c6818ef4a42cdb6d43ac79fe3b1992864de132ce60"
    $a6="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
    $a7="da283ad64aaa8dade96b1a71e19d9bb0a59d346dae1fafd0a41aa452fa9471372b2fed29d75429f0aab977aaf01215700f166867879afc88565bc0bfc81b8229"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}