rule sha512_hashed_default_creds_openconnect
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openconnect."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a3="9229ac15237b0bc3bef9683db7096555c455cf50fc76671a057aedb4518f5ff9c5c831e43cda54a17b68bddb15b39006f91ee1ff8e2593eb2904c11401e0af51"
    $a4="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a5="8eb3aef537d38daf8714dc53a3fedaa3bc5263303f8f4841d4b0308d38939ce3b4169c1a26fbb686e5734cbf6681ccc73829ebafc603cd9083bb1513409ba9fd"
    $a6="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a7="49385d39f875d7b24b2e0fbb8ada43c9213afa476b4307a18b734d97656168b0a6a85c9ba48ab825ac90405f60cd5fd67cb91625c8c3efbe1d2ab70deacf0823"
    $a8="84c0a44a2699e851517bcfd6dbe85eaf1fffaae8554a2ba6c18e64713e7ea22899fe1f9ed4c163569b9ed7942af1bf94d225b2048dfc0c84d1eb6261268979ec"
    $a9="c429443a06764c82d4f2aabe79af3ce68b909a636e2065de0b337b4ea558350e96dd0b9a60322004ee86ccd691aad7f6467cd71e0f9044e71ca684e797d5a788"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}