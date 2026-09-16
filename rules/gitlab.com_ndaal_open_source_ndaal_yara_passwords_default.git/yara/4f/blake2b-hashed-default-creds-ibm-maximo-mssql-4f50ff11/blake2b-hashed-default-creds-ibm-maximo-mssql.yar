rule blake2b_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab91910ec29db734d2fee5a2a71abb82abde4395aaa0ba8255169deb665f520f93b069c06fe983dafb922c87dab694d8075de324c1d8a53414965e6753b716a8"
    $a1="ab91910ec29db734d2fee5a2a71abb82abde4395aaa0ba8255169deb665f520f93b069c06fe983dafb922c87dab694d8075de324c1d8a53414965e6753b716a8"
    $a2="50ba0a14118047cc3d2e4693cb1f1c7737d0b0bd0015fdd0c514c7c07d5b5169905034ffa5856161281e9a2f4ac81728d1c402f7e38f995714ad42e9d06c9fac"
    $a3="50ba0a14118047cc3d2e4693cb1f1c7737d0b0bd0015fdd0c514c7c07d5b5169905034ffa5856161281e9a2f4ac81728d1c402f7e38f995714ad42e9d06c9fac"
    $a4="3be298bf52d69efabc23e925acbd63425fa77812b7accb18349b6d9c2ada00e3afa5473c6e396ed682293c7ae5fb750f87603bc03226c2a16944d91e7c0d2715"
    $a5="3be298bf52d69efabc23e925acbd63425fa77812b7accb18349b6d9c2ada00e3afa5473c6e396ed682293c7ae5fb750f87603bc03226c2a16944d91e7c0d2715"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}