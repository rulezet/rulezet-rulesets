rule sha512_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f6153cb5cdd386d53707c3bd2c0c68421a9a0f1358fcc0b927cb35cd8351fe6a3e7fda09671f5bcc1aec03907f2bbba8d1e7af158f20a2c1340aa0e8be5ceffd"
    $a1="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
    $a2="40d380d92f53ad12cf2194596874a9179f1ee3f92e8f7c994bf94db3291abb89c3ff351ed2b91130157fc7d32f842ced4b998a9de6e0e01d987a28d96934e6cc"
    $a3="b67f71a782accc6e99740fb4d0295572d81c9a15f8e9e24174e0d1a2a1cee7435d1a99833490983eaba65c68022122bcea002e29fb8d76716e97db79741819dc"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}