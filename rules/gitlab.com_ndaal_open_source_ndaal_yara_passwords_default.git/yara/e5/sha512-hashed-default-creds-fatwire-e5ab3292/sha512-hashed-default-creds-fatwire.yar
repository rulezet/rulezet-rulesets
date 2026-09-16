rule sha512_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6250924f80ae1be961b1a452d6d47a6ace0b160772a11caddfd8d8154e5974230317c00106f8401f0c4d34d3e0f838ee7cdde63518d508606cf8082db1bcf2db"
    $a1="6250924f80ae1be961b1a452d6d47a6ace0b160772a11caddfd8d8154e5974230317c00106f8401f0c4d34d3e0f838ee7cdde63518d508606cf8082db1bcf2db"
    $a2="7f80ca2b78ea3b1a73bcb33c41def1525197ec3963c92e977eff6da07f4392853897b2fb2466d6258035463f51f6ef638b97c69bcdd6fec316549d279c1622ed"
    $a3="3b3de2a49852b1d480f8011f5dd8eb5576f97045b2e13c0f3a3807d8b9d05837d1e360e18b2c38088dff8809c2dd03cdde2d9ed58abe1eec1fc41d4b20306992"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}