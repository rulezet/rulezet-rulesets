rule blake2b_hashed_default_creds_radio_shack
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for radio_shack."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9849fb3db2c78c49af0d2eeee88c7f0a203e523fb303f47f531486c4a2bb658bdd8aa59cff04c9a18a5fe1f2b2b3c674607d3020868549e8435676add59298d3"
    $a1="892c51ab4cd4321cedf7488172499d158b1a43ba46e138e28c8f03cbc5029ec88069ee1b5084eaf7df7521068223d7ae8833993d3bfc52dd229ab1bb45029391"
condition:
    ($a0 and $a1)
}