rule sha3_384_hashed_default_creds_utstarcom
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for utstarcom."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="308c398ebb56f272e4bc316a45c1145fc374b5d15d0b64f78c6294b1a2d03370b5f3d8727210e821f8e9bf88b71714d7"
    $a1="308c398ebb56f272e4bc316a45c1145fc374b5d15d0b64f78c6294b1a2d03370b5f3d8727210e821f8e9bf88b71714d7"
    $a2="3db0d9634f834725ddf5752b8f756c3c48cfa64987236f68b42d66129cc3b7dfd12b0b50b446f18600ae4520406f4da8"
    $a3="e5d15c7e25cddce4fb8cc889d39db219dc9a9bd4025517a83fcc56ebadeabbe6bad679ef86b4ff04a69388ff99a0bb0e"
    $a4="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a5="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a6="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
    $a7="0efb5a9d99b64ce5a808754d55eed93b4c65b6307484c298bdc2d3732999f21eca47129421c162423cf115e5e733b088"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}