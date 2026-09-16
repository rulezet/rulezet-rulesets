rule sha3_224_hashed_default_creds_ascend
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ascend."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9be3fb156646ef4114be768ffb84fa2fe91909db0a56a87f13a55dd9"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="def073a2b31ce23ee32457ab705a51f1abbce8e25c327dfb36c98873"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="78b3f0c8476104cf533ef1a8f77b7f941e9278c0e889a72d9b986454"
    $a5="74828cab36f773a4a1323c52715599241fe70b3a6bfb9877a96d0ff2"
    $a6="9e7fb7d8aeae258f2cfa631463fc989f13ba0f90f852bac101f2d0e7"
    $a7="ef7288e18476c5b2efb6d043e4bd7f5d955df401618360641761f6dd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}