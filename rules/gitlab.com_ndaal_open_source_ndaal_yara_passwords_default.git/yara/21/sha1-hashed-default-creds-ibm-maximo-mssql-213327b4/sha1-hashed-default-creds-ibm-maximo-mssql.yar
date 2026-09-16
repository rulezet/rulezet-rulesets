rule sha1_hashed_default_creds_ibm_maximo_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_maximo_mssql."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ea52614215568407593a2ebfbffe7609323f537"
    $a1="6ea52614215568407593a2ebfbffe7609323f537"
    $a2="3e86a541edbac4c26942b2432d02afdd590895e1"
    $a3="3e86a541edbac4c26942b2432d02afdd590895e1"
    $a4="c023aa5bf8e4e57631de80dd3f3748ce6ddaf97f"
    $a5="c023aa5bf8e4e57631de80dd3f3748ce6ddaf97f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}