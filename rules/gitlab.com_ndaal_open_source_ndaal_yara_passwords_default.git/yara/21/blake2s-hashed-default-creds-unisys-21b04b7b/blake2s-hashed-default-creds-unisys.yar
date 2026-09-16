rule blake2s_hashed_default_creds_unisys
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for unisys."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="760c075f1ad787cb9d83deddbd4c3fc528d41650af9c22929f7165fb0f198470"
    $a1="760c075f1ad787cb9d83deddbd4c3fc528d41650af9c22929f7165fb0f198470"
    $a2="f3683bf464195f998f521fe213497abe433d504f303e385624da0038137148b9"
    $a3="f3683bf464195f998f521fe213497abe433d504f303e385624da0038137148b9"
    $a4="8098327fb17813bd681a3a8353931abd66b3981a265bf43178396cc230868b03"
    $a5="8098327fb17813bd681a3a8353931abd66b3981a265bf43178396cc230868b03"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}