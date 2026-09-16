rule sha224_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
    $a1="ffa2a1b27f9a7b2bccec3d0efc2b0bf25c178be55fb8b3fd93c8d77c"
    $a2="f0e8b3c2dda2512b55e4dc5d4859b1877e98109c7c4e755ccd2a5763"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="e9a17768d48637bcee3b5ce3ed21ccdb2c39c5d9b089444908208b2e"
    $a5="6cb0e3de5bf9bf402fd61c59da949ea0eb90e08c24c5da49878ffe43"
    $a6="e9e648bddc054e8643beb7194d056d9ff74dfabc2ec32376b8ba615a"
    $a7="e9e648bddc054e8643beb7194d056d9ff74dfabc2ec32376b8ba615a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}