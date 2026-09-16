rule blake2b_hashed_default_creds_ibm_imm_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_imm_web."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="17f2a5ce43340ecd940b40392b47e8c42978735c5d4db42aca7012b1997c3f82eb6b77582be3545b1cb292af4446be8d6bcae893da0f87a2f33423a217eb23ee"
    $a1="af3e42e32f9fce311a555271da2b8ddd790a0b996eed9fa7dede54b488e001f05d54fc43175dbd6b0208c786c317dcb187542ec01aeef8aef5072dd43a11b3d8"
condition:
    ($a0 and $a1)
}