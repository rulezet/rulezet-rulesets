rule sha256_hashed_default_creds_server_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for server_technology."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d335a3bea76dac4e3926d91c52d5bdd716bac2b16db8caf3fb6b7a58cbd92a7"
    $a1="800fd460d26ee2a1ca23c523b4d17bac8480761ce4224f27419dae1ee52038c6"
    $a2="1f36df49fb1212b7860da023f4c28159e16070cf8f4e4934c76a9ebfa52d3671"
    $a3="dc0e3ef8ba6780d1e9d537c3047f633617f6947e9dffa34780e7cbdf6c247191"
    $a4="c89296cdecdbca0b46e74e4d7d25b93ad19b95a88b1cc59f13b0e01975693424"
    $a5="7ede771b4a6bef4621de8746fd94d004683c2ef46808bc0b5b2065e2f8256cb5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}