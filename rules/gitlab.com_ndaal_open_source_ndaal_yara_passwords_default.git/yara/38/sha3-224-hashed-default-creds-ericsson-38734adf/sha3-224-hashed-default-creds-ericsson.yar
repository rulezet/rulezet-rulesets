rule sha3_224_hashed_default_creds_ericsson
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ericsson."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
    $a1="43de4e176bbd06c3f84e8ffa24abc2b9ccf619eec3f278b3aa85be77"
    $a2="56a9602a1d3111b4a5c6c78e6210e0d431718b1a99315e78e232c27c"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="0b1efbd8a699a51ffe71726a2742d0b40d5c11855dbcaae37f5c104b"
    $a5="4de781bd81b0af5224b5f55613c4b309b479bbcd6318f6fdbbaa3457"
    $a6="f31ce4fb1e19793e94550cf556862f9fa446dbfcc835db2b461f0026"
    $a7="f31ce4fb1e19793e94550cf556862f9fa446dbfcc835db2b461f0026"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}