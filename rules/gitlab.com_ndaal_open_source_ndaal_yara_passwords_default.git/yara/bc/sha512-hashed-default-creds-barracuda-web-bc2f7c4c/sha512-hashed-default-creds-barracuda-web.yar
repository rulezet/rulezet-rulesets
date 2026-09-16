rule sha512_hashed_default_creds_barracuda_web
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for barracuda_web."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="0e49ca158193b11a6bccf057ea453677a49b7a8bffcd6b155815bba9845e5f99db3c65d9fee5ab4eec9f49b09e5659602cc257eba8fecf018a87d22013513d33"
    $a3="0e49ca158193b11a6bccf057ea453677a49b7a8bffcd6b155815bba9845e5f99db3c65d9fee5ab4eec9f49b09e5659602cc257eba8fecf018a87d22013513d33"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}