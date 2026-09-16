rule sha3_384_hashed_default_creds_datawizardnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for datawizardnet."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8515cb06235da20af87c4f5bda3c5370d04368e323b7fcfae33419f1d173e4d92f4491596e8607481e15a3bbdb370b5"
    $a1="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
    $a2="29bbaaf5bb4833d1ee99731dd706c7564d545323dc38077324710346b47c672f6cd95b095b2ab146106b26250aa52eb8"
    $a3="3bad431ae955a326af10fdce3efb08932e403c5a8be7befa9e02903b12860296660817a88fe0cb3be1d0371532fac4be"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}