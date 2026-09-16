rule sha3_256_hashed_default_creds_xerox
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for xerox."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8b7bf81434969692a76642194c4f25fbd31b6b1e7ba3085ac508445171ce0be"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="37b0edec323a7fc924dec259de1b1c59164e2ede27fd51e830dbd6bde7d00839"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="5db035077ffa9ed87f7a9d8f5317a634728faba1906e8f008d76700ef51fcc30"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="d8b7bf81434969692a76642194c4f25fbd31b6b1e7ba3085ac508445171ce0be"
    $a9="7814d1fa7209582328327cf2a11fbcbad2b14991f10bb9dc6ad4ec0dc6d950ed"
    $a10="b3464291a58f65050d16b715a13e1c4d422785e733f7a9c44e381dfe620b5855"
    $a11="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a12="e7f39b4119337380e823f0acfd559e77d0a770e93d62c3e9b07aded5a642088c"
    $a13="8e15d20bdb7674d97f6d9ac31cf74f9c5bc38b3fe9ecf54641ab08044ce207ee"
    $a14="9bfe14c9798fc1c606d8d8d00564bcff734762c8b93dab25a60ce5b965f802d0"
    $a15="b4a26922e0b4a5fbbb62fbf14af3cc5fd2d44fe0462ca15b1439914ab2f920cc"
    $a16="14f360e79af9e6a55b25347d8e5dc1fac1ed4255d83efe35b52fcf404e89c84e"
    $a17="51fe81804398b0a51cde487ee95b758a6d2e77c151f4d6d0a3752fa2e2c62e31"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15) or ($a16 and $a17)
}