rule sha3_512_hashed_default_creds_kodak
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for kodak."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe1b65262021ac83a744628d789754b19980d9735033f6a93c4900a1b8752b97b73a654a78c51486edb6684abe70431e18d48e96efa81b83c9645fbb7e484b2f"
    $a1="0fc5e04fa0532ef97fc03dab2928a6ecce56d9ed8b022adc8d1a3824907e0ebd9220445bfe0598bf03a53934331b43b6d620424c8d24c747293c92e6cf215832"
    $a2="fe1b65262021ac83a744628d789754b19980d9735033f6a93c4900a1b8752b97b73a654a78c51486edb6684abe70431e18d48e96efa81b83c9645fbb7e484b2f"
    $a3="289260912ae594f3c86f7b268576f5161ed747b8d9693e53d6397f7a1a5c66b7976812b9938ec5e248ba37a7008fa63eb50f24db27d5958cc2538194b4f8b78c"
    $a4="fe1b65262021ac83a744628d789754b19980d9735033f6a93c4900a1b8752b97b73a654a78c51486edb6684abe70431e18d48e96efa81b83c9645fbb7e484b2f"
    $a5="f415ac98c933780b31622dd2d05fc9f83df1f585f0db108559eccc8a8659b7df653cf70f5a2fb86b44bc7f88cc566f9a669aed1a07d063de75963cdff23b567b"
    $a6="6cc43bc019055903f09e4183bdefc203b4581384bdd60c80def38cde01a23c80eebd2cd07f09da3c0d72afef293a1a9057a993993f7fc4ed3498ef8032899234"
    $a7="94306468b6d78f5a35b5444e846038770f57e37f711996fbd7afd000e963a6107639b1a839c1c895fce1a67386c0c6923bd7f3db35a9783289158dd2d00a8966"
    $a8="f1343b3626745557e40e3014d28a07766a31c925778a9509b048d518429b72973d8be7ff9ab3e78597885f321c5f4786e2a61b51436d868479e40cd7daa91242"
    $a9="f1343b3626745557e40e3014d28a07766a31c925778a9509b048d518429b72973d8be7ff9ab3e78597885f321c5f4786e2a61b51436d868479e40cd7daa91242"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}