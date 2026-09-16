rule nthash_hashed_default_creds_janitza
{
    meta:
        id = "3aYqsD2lcGXFq3pDhb7Bo3"
        fingerprint = "18d2a33b6dabe26a4355aff4cd1b1ab68b2f386af799e3aa65bda7041ede0b0f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for janitza."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9a916ea108b915ab51ff86b8c82293e"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a9a916ea108b915ab51ff86b8c82293e"
    $a3="823893adfad2cda6e1a414f3ebdf58f7"
    $a4="54464a86d6ccfe7df6dc96c7fec07556"
    $a5="d31ed0b35d6df7e3969f93678a42f676"
    $a6="a9a916ea108b915ab51ff86b8c82293e"
    $a7="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}