rule sha3_512_hashed_default_creds_next
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for next."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9700a92084a378567fcbfc158aa1e53a53d06fc4cf2f2b3f0a08cc0c41412c0a495df571928a75aea875027705a4aa793b0f4f7a0f9e32287e9a5cc2175fc3e7"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="031fc2625ed64bc0273108e7f60005881846a2625569ea6f3e303d8d5748f5017db27bf3971c1f6fb763bbfc53d29ff743902771c08c5f61ad62af7cb77ff3c3"
    $a3="031fc2625ed64bc0273108e7f60005881846a2625569ea6f3e303d8d5748f5017db27bf3971c1f6fb763bbfc53d29ff743902771c08c5f61ad62af7cb77ff3c3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}