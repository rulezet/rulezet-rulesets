rule sha384_hashed_default_creds_beck_ipc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for beck_ipc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="372f16e3e7c601131c1ca6987d3c855ba182befe19463b1d3ae21f7b441ba1e1d5ca2a70c3296bc03c08778ac1dd4934"
    $a1="372f16e3e7c601131c1ca6987d3c855ba182befe19463b1d3ae21f7b441ba1e1d5ca2a70c3296bc03c08778ac1dd4934"
condition:
    ($a0 and $a1)
}