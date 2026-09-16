rule sha512_hashed_default_creds_hirschmann
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hirschmann."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d32997e9747b65a3ecf65b82533a4c843c4e16dd30cf371e8c81ab60a341de00051da422d41ff29c55695f233a1e06fac8b79aeb0a4d91ae5d3d18c8e09b8c73"
    $a1="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a2="9d9f1d99d6a2e8488d0c330269f0a15d1f56bd4b309c840ff678fc6a32f15e2cf6efaf76e4d5471e7af9f88a12014a7ae6f91fa2e08fc622493920a555290c93"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}