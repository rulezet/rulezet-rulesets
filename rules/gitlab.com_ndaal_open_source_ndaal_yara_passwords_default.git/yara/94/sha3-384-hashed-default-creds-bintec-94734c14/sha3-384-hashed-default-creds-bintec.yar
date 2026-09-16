rule sha3_384_hashed_default_creds_bintec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bintec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cc69a08d275b075f625a74a92b68d59cdb18d26bc91d6f392757a925028e6a410caaaae5a2cbdf3eab10d44fb5c40ebd"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="fd08db8d575a4916e9d1a1820713b3de570aa2b4d7bd949af2750c4c3c02bd58e183f302b9da7d672a474d461ddbad19"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="c653a378f3b0f4530aec7b687affe546680b5fddd1247060b0e78895d92613f83f11d6d4e35aac659c6408230ae13003"
    $a5="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}