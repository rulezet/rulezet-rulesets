rule sha224_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37bf6de17154b357dae71719d78e28694183c26fd0999d8cdd23e8c4"
    $a1="37bf6de17154b357dae71719d78e28694183c26fd0999d8cdd23e8c4"
    $a2="9fab6d8895b0e510404321f0a49de91b57954e9eff4fa6a657b4ce39"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="9ccb03ee072bc1417365a249f925ddff6bf050841749e0ed0e141fe4"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}