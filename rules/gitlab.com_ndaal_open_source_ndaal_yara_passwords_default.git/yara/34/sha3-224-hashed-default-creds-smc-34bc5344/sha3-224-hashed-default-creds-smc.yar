rule sha3_224_hashed_default_creds_smc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for smc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a1="60d14e19989ed5a1b03b31934f189be69766c5692ae815bebceb4390"
    $a2="c40c0066051109e6be0e187914098b30e226d67555b5ada283a95def"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="9976702f28a05a97104c42c54485cc5ba9934c2678cfb760019f2b3b"
    $a7="b0943331ec6d77e02786088264831bfd9538b613526a25657ecc354d"
    $a8="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="1bc5b8b12a5cd74e40ec2fb3046bed5ec687e1ce4512717ce9a5d92c"
    $a11="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a12="798853769d763e8c45a872e54953992c405f029f93dc99a342887a88"
    $a13="cd2a95bf34c36874110599b4da7e44326c8bc8e17e91753dba17228e"
    $a14="cb728babc0fad99e8568d29b85f963fe824744f5fdefbfa2e6645f94"
    $a15="24934871b4dd5d625da5ec9346416245e6e3789dd6d7e48bb870db3e"
    $a16="ef104e45e2248bda1fc499d3b77ebd7e857a3aef8a8bdfcdad077bde"
    $a17="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}