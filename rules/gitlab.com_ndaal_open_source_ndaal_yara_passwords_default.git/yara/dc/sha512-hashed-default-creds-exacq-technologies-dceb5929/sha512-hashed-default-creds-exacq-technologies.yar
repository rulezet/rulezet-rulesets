rule sha512_hashed_default_creds_exacq_technologies
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for exacq_technologies."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f4418a288d445b1754f3c0616d3df81bdcaeb19ef617d0e76715968d1f578f29901d3852a55d75025e6f4ba88ffeba41a7f2b2ae882ff50717ddcb464bbabd02"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="e3164e72d7ac3d293675ed0e42b81ba7773ad11451b1aec9c8d074b799aac6efb806b39db3d850b175b13289c833505642c385a43e50a98abeffbc81e5a6388c"
    $a3="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}