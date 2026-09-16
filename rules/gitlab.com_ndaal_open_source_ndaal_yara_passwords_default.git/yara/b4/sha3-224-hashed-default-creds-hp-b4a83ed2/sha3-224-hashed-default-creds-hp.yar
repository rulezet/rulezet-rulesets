rule sha3_224_hashed_default_creds_hp
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for hp."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="3f73a315f6a76f6d1088eafec0bc432037e29e9b85d8a4337ff78fb5"
    $a3="88bd6d1cab4dae85d8c18a559575e965f30badf481d465a6f82a0baf"
    $a4="a96ee36d7eac84d12543e809ea04e233cd37c2a04456675a96d867ee"
    $a5="8ba353b87f08b97351064a0806a18e36e2f342cd26a8b95bc3cdf00c"
    $a6="f1e81b1f7302c580255b498d5490b55c65c57dbbe93a4ec3ea222656"
    $a7="8ba353b87f08b97351064a0806a18e36e2f342cd26a8b95bc3cdf00c"
    $a8="4ad8763adad18393abebfaa5e2393e2446d6377da995a0e0e82b7d8e"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a10="0f81b51cf2be501fff5405ce1426bab4fb53a8bc0089ad4e19fa38a6"
    $a11="d3b41d589a345a9f032ec864eb83dcf994e92c42a7b7943e12d7a493"
    $a12="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a13="a3c540c56f53058e38a1a05d992c0196ccda6c35e47dfc695c453a3c"
    $a14="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a15="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a16="6f3ff412ba937306d6557af1afd5214e9f58177a4cbc4755d9e2d47d"
    $a17="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}