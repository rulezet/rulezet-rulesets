rule sha3_384_hashed_default_creds_dell
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dell."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7a887909df67a32ad28776d54fd260459f83e6dabb13471bd54c426a1b2b8e1f980383caf90083ab9a9581b5d662e72"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="48913b8cdf4367670a1d16243ffda6bd8b4e95eea9be8ebda1e41316d6f24b39090790e97800f80bb5f9d15f215616b6"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="dcee086896e14c296ff7d0d13939e8eb5571a9343f19ab1bd9280d81e4301e8656b61b0d14cf71422fdf6efc3e74d100"
    $a9="40d3f0f3b63e86d851c20b0dcbef911cb31a56e65f2a59f5b97dd3d47658b713211c76c7ca838342ff78b1bdd3fbdf89"
    $a10="55c64fec0ec5ebfa89674e5b259187849d53f1103effd7abeff4d8e34c0444164333aa9c011f0163e25bf3c07799e213"
    $a11="05278801e977cd312fc2530cb4a77a89a1b5f21568cb762f6706f80fc9cbbb5ec7c37375a4cd667695ae38e8988cfed6"
    $a12="c3166cfbcdbcef03cbce88986f46fa957a133073ef15d5d73c2857eea941a3fe7321515e03e1293e1fa8f514d54ff4cb"
    $a13="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a14="0242332157f9fa630c5fd3936cc897a0d6be23b7708738605be81a4895eac87a5fed7dfbaff90db486bcb229cde645e4"
    $a15="39bc1f48c0ab323564360bf47522ae8bf6482281525d5ef5e45081cb9c69cc506698a7a795032d7aa17e7554b62080db"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}