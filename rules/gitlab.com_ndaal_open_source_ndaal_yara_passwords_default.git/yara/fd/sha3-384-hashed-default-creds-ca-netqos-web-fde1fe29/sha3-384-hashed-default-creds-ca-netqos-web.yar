rule sha3_384_hashed_default_creds_ca_netqos_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ca_netqos_web."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c82e6990c1734f950c4f88d3fc736debc43b14be4bcf9664d01d50e0c1a8c0a1011de2e6714d5a7d6887f25255edd305"
    $a1="5e4fecca7f483440a85f2104ab1cea61eff9b9e5495d3b021e965cd345f88586aa0d4908ce5d72f7da6ee5c067b97615"
    $a2="c82e6990c1734f950c4f88d3fc736debc43b14be4bcf9664d01d50e0c1a8c0a1011de2e6714d5a7d6887f25255edd305"
    $a3="9abfa7785611364bef23ecff1692dd48ef85d7ca6094fcb75f077b1427b40767214eae8aa9a65a4d738c40baf13860e4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}