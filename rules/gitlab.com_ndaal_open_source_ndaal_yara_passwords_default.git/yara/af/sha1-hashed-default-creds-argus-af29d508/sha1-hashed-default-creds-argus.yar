rule sha1_hashed_default_creds_argus
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for argus."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab4154a7c451f56e9b7ff1537758ddd0c619f8be"
    $a1="ad475743d42de8130fd913c117213e3703707b88"
    $a2="80fd108a3d7a5a3c4e2cd0c4da36c943099e006e"
    $a3="80fd108a3d7a5a3c4e2cd0c4da36c943099e006e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}