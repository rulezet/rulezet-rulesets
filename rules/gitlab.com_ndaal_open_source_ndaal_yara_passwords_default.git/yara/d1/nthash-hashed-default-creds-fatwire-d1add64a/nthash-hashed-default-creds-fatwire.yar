rule nthash_hashed_default_creds_fatwire
{
    meta:
        id = "6pYvaoYPOzF8pgPNss0H7o"
        fingerprint = "4216725ab7de12e6277cb066570a4e57ae2870747d2fae6d568922f634972f74"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5998ba1d1a0aab4bfb8d9a313866bbcb"
    $a1="5998ba1d1a0aab4bfb8d9a313866bbcb"
    $a2="fd2a401a070a77951b664727b52f2e3d"
    $a3="24e85f35a4890114b5cc035e16025486"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}