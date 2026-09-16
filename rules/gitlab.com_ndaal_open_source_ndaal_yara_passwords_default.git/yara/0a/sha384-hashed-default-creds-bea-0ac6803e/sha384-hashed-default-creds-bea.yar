rule sha384_hashed_default_creds_bea
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bea."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"
    $a1="5759ba5b71427e5ee5a02b2f71ea7456a0a2094f93d03b38d43613fb600c0a30924a8d2b78a249d7e9ba17840a6e5801"
    $a2="7d376d415ff3adbd0789a49e08380520f5e7822b9a6fa5039943bf2eb12def6321d3899471be27e27f69e2fe8a58e29c"
    $a3="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
    $a4="f0eaf6f35ca40378802883b7cf06790eb1c7a520338c57abe49124b3bacd1ee579ee4675c444a90045c93d621fb49bb0"
    $a5="b8aa302725e1ab34a6085f06ba6cf3f7432bc68fd8a22d1b55c97324a687c9053899307436c0cdfc979429b8a71b213b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}