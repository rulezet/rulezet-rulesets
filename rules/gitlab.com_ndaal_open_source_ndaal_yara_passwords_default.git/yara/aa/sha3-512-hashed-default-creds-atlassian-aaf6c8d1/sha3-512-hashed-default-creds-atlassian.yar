rule sha3_512_hashed_default_creds_atlassian
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for atlassian."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a1="ed49c59a1102e2d1a9e587ba701749ce0a830119501738eaafd88dba2b1ceacfff416233e480b370a2ae5984aee680b69eca0fe6ae2075e57ba3f0f6394d4bc1"
    $a2="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a3="7201dcc5994fb5d74bc79c39ed7c755924c0d29a71f2ddbc257f35c69f06b4f730b357f71469e7087597e77e9538c300ea5c988dcc57e21a3f93a9a1d466310c"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="c4bd18fa15530ea1532d144aff5e7665dc92db28e03c7a0a421d1d0e16948c05178f47df0d5044c35a2c8a2be82e3ec881e81d4127dc6c301a188be799e14aaa"
    $a6="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a7="da0c5013c9573a8180a672f335ab7d8f7dddb4a39d71514c40193fa537afb39fadde316eec144d73524adf70e5bcb4b1d5ba67150d3d52e5df29058418dc5a57"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}