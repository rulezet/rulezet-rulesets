rule sha224_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="678da59480e324c87dc0a08479b25ad36a56746966ec0db347eb1700"
    $a1="aaa4bcff925fb93b9014e8d9f80453e7f9eed710d986541b176677c0"
    $a2="bddf1d3f6f46a4ca2abf6e1e1174a6905d7e632a94fcfafd30205997"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
    $a7="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a8="208464db6cc2b9f7d14779c6640b9abde4cd210726afe280926cfcfd"
    $a9="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a10="88a89826f5cf17caee53b8f054fb5cb7e54809f8de3aeaecc7a6de16"
    $a11="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a12="4bb4ad5f08f86191dfe22bc534613c50096825d9b8500fb3e32a5f55"
    $a13="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}