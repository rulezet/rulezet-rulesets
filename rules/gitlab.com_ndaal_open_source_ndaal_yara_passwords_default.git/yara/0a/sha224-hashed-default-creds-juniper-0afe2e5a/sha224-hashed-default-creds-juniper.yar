rule sha224_hashed_default_creds_juniper
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for juniper."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a1="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a2="4279fbe1067b40837bc33323de5d6fd1785fd7f7606a79251879e99c"
    $a3="4279fbe1067b40837bc33323de5d6fd1785fd7f7606a79251879e99c"
    $a4="5c69bb695cc29b93d655e1a4bb5656cda624080d686f74477ea09349"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="dd7ed3ca1388703a69f0932c659b7ef08dd1e48ba64cd93a5949e6f0"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="41d8ab51aa117d8121cca391219c4c9adf1fd888417cf07504197a27"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a10="43779d1eda1cd9654de397b9311958b739d4ccef98e7f1e9c43d94ad"
    $a11="43779d1eda1cd9654de397b9311958b739d4ccef98e7f1e9c43d94ad"
    $a12="e12503cafeb0fe81c90cb7be772832c6b1bd22fb9329425e936b8cbd"
    $a13="0f726b72946abd860c0972fa8b50fc3c7ee6edcdeb23b42d6684e708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}