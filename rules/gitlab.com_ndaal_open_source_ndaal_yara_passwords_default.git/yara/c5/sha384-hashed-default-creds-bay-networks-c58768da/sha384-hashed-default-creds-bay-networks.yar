rule sha384_hashed_default_creds_bay_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bay_networks."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7d376d415ff3adbd0789a49e08380520f5e7822b9a6fa5039943bf2eb12def6321d3899471be27e27f69e2fe8a58e29c"
    $a1="7d376d415ff3adbd0789a49e08380520f5e7822b9a6fa5039943bf2eb12def6321d3899471be27e27f69e2fe8a58e29c"
condition:
    ($a0 and $a1)
}