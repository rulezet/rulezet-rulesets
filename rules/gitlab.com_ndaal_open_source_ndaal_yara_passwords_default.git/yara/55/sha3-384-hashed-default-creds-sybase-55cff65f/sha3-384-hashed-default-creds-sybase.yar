rule sha3_384_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="12352f148b962be3405fdc721550dd617e9d3b97b038ea6f0219df002dbfed2a1e83842d6b7b2c426589cf3699f5ab55"
    $a1="2e88d0c3103abe99dbb748ae1cd719c2a1df734494a398e6284de4a497fd60774b16deddb0b6e1a36f5c715cbdd275c9"
    $a2="05488b0218445ecb3d45325f70fa27c4867f71a78236deae14a4299a082ba67de1d52dfa2c59cb227e1ed16f29b65e8a"
    $a3="be66f54d071afe509f093ce39a02f1a7611035d17014ea0e01dc82a4c41997cbde86c2b667e08c34383508ce96a7289f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}