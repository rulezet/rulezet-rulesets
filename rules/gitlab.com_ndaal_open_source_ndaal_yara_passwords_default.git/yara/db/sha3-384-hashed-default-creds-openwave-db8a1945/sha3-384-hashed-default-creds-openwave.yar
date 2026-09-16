rule sha3_384_hashed_default_creds_openwave
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for openwave."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5c81e5a16deda72d7a26d62812b8de9ee35ef007af59616c1a0de71bb325f44f958a4825e294f0a10e7ffbd45de06326"
    $a1="6e13691fbf307e304df38ed5642ccedd28d9bc7fcc0e199845e2aead16380ded2e7061a6c2e684411b6d307d6ba06c78"
    $a2="857530910f65a899885215258b9b560c2f98fc3dcee68bf3aaf710827d4835b5b4f48ba03dbbe618360deca6bebd7236"
    $a3="f518f8c6ec3a806a5ad3cec99463383f94edf16486960bd62882c11ab7b75cac1f512ec2f5b8dbef497db829643c4418"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}