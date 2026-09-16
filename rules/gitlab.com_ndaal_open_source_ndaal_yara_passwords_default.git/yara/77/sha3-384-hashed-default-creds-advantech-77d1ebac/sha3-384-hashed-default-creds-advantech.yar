rule sha3_384_hashed_default_creds_advantech
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for advantech."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="b64713320b04a6474786484b17e0b59f03c06ee022a65bfbe436b936a08e1a8399c3c936122fb0a43c9c0a030e696eca"
    $a2="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a7="be761c325bd65980169af0dff977f9d34a6e3dd9143ec984ff54f193b06aa1fcc49fe997d8769f6052d263b5d59baee6"
    $a8="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a9="43d90448744d5ae5f38c8dc894771ea4820eece7e566e101768132daf4042c3386b746fe72ca836d66ae4ddc3ec4284d"
    $a10="748e6ba10d65d46666cdf2980381614d19c05b6691c45900f68841a10eeff3bea0bbcefd7dd6cbd99a067c7942ce9068"
    $a11="48aec81479e24dbbff7f77d0f52829852722af06b1508de71d51b5d275c5a8681651416b0615ec2a1cc1a421067a378b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}