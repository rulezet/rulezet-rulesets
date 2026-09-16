rule sha384_hashed_default_creds_kronos
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kronos."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be5a2a15447b7344c805cebe857fc9e392dd961813990d48a5caf265aa02717f4f3631c2fec1e79cc9130b4d5ee00e50"
    $a1="353e2073997b897542254a1e667e4c96d323368a990b9f3b17182b2284a984efae7814ab54153086e47bac672ca21646"
condition:
    ($a0 and $a1)
}