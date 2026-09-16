rule sha3_224_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="36a88513cc12f0fb5041f9417b49822d1f05690c1b80f275a6c287ca"
    $a3="36a88513cc12f0fb5041f9417b49822d1f05690c1b80f275a6c287ca"
    $a4="792b61c9b94c490a85867d4dd85d451083b24411c070f09bcdf0f7d4"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="9ce1d539b79cd6f641893c7c7c20a116de3b9026652a017f0520802f"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a9="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a10="d218f30523776ebb67cf92ab59e208cc4b920880ad19245c5343bd23"
    $a11="d218f30523776ebb67cf92ab59e208cc4b920880ad19245c5343bd23"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}