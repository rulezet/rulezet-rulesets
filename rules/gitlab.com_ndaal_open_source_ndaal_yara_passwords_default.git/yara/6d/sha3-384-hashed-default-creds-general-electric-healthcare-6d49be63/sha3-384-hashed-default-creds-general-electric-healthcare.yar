rule sha3_384_hashed_default_creds_general_electric_healthcare
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for general_electric_healthcare."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a2="66f11b3fb9d7052c36ffb01d30d97439e85ec3b0d981b05910e14034caf76a03063eb32f5b67cdbc697b963deb2915a1"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="66f11b3fb9d7052c36ffb01d30d97439e85ec3b0d981b05910e14034caf76a03063eb32f5b67cdbc697b963deb2915a1"
    $a5="66f11b3fb9d7052c36ffb01d30d97439e85ec3b0d981b05910e14034caf76a03063eb32f5b67cdbc697b963deb2915a1"
    $a6="40e12b42de129576b2788a6f0b84019732e616b8eab62b424b2601834c00f597b61cb3ea9e69a40bd9afc3ef0f4cc823"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a8="7d000799e7e657963926f34a56401c5605e4b967ce11ffd0385c4bae2d48bcd86f624f27df61fc9143886429d964859c"
    $a9="bb6c0384ffc50cc63b12cc2ae64c29452204d4b405f91896a48762aaa2a183e2685082a3c97593cc19cf5506f0556472"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}