rule sha224_hashed_default_creds_fatwire
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for fatwire."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="02b20320af5c03b4bd347db62f53ee30edc4c3d8dc8ac4a7d6328939"
    $a1="02b20320af5c03b4bd347db62f53ee30edc4c3d8dc8ac4a7d6328939"
    $a2="e5ce190ea5c75c2c83fa41502de4b8db1d77000e4442aee512d4c60c"
    $a3="8cf19140cbfe4f207d6d66ff168a91f572ed23e39e9ced1523d8317f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}