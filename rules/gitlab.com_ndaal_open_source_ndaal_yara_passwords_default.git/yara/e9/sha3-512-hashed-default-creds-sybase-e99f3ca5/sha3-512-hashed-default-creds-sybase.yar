rule sha3_512_hashed_default_creds_sybase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sybase."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2b2aa94b914d29b3c350ba58b4bc7108f8169dbf26309ac5ddd439421803a5bfe26a9665fce60fdc20348a2348d86a909eaa9d6921a9bc6c9daa8b6a4433e68c"
    $a1="2b165fb340db361f9351ec845a3824bb58317f65fa91dc6070e89400520e3daa20b0db0627f67847b3da532c4cbe04ca63900de44d384d1f90c15ace0bec73b1"
    $a2="95f5013b88e0c0e71f9741e05a0973e852ca28770c3ed813f7edd7f8583add711442ffa2451cb90a468aeef0502a77828417225a758a3f4701e6502c8d450a58"
    $a3="3dd4af76058f55af859b1f5855ead73f2aca7709359789d82ff8635109aa22aca95e43f76c7aa93e75922de22e2a203bc31856dab6e448be8490f052248186fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}