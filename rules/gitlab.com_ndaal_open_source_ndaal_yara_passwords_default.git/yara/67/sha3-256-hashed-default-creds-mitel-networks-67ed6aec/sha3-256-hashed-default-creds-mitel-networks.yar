rule sha3_256_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c9bd6c4b84a74b52a293499a8fbd2bfd40187e80420f3faa9bd2e1ead156d243"
    $a1="5fcf376109a06d70ba53ebe0e363b17148f276c36697aab04536499243014af3"
    $a2="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a3="f6238a3654d68b8148200a053d013ec6c1caf6e12b24679c88d645f80c686bbe"
    $a4="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a5="9cfc8ef98f2e43fe014b9c50965c7d63182ccf14fe156135cefba847a0393051"
    $a6="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a7="338907d05f4e53a01641ebd736036e4e07ea5cee1ba5bcc058b7e89ce132e3df"
    $a8="c9bd6c4b84a74b52a293499a8fbd2bfd40187e80420f3faa9bd2e1ead156d243"
    $a9="38af59e1a1498ad9894d11fb12a04ddc77dc4837f872d8b0b970ee0448ac8dc9"
    $a10="8b4f3f4111c5687d046a8e998d25660dfff6e217034f2a42e19cc7f9e24fb5b8"
    $a11="addd07e476d8cfca0b24700ba0c45371172ea9c670e883d49df77e053d09c379"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}