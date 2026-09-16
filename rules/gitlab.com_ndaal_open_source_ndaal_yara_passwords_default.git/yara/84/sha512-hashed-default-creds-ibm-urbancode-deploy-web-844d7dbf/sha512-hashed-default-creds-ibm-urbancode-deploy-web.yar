rule sha512_hashed_default_creds_ibm_urbancode_deploy_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ibm_urbancode_deploy_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="042861c8dc1b8d677debe4875e5683b430e4ca11e8118dd1ac58040445ea286e607584bc03227c3e33bf9d8d734f8228eff3143e42a5f5ae3878fab1199bee39"
    $a3="042861c8dc1b8d677debe4875e5683b430e4ca11e8118dd1ac58040445ea286e607584bc03227c3e33bf9d8d734f8228eff3143e42a5f5ae3878fab1199bee39"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}