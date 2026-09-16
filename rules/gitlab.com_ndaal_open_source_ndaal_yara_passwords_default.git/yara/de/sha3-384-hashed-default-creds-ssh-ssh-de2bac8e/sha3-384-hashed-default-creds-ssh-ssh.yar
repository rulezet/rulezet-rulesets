rule sha3_384_hashed_default_creds_ssh_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for ssh_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="049de04e34b19f24d355804c041ffdd7dbb0aafdc60641569ff4837a0d61bd761bfced258bd6fe2e89fcaa6533ba5449"
    $a1="049de04e34b19f24d355804c041ffdd7dbb0aafdc60641569ff4837a0d61bd761bfced258bd6fe2e89fcaa6533ba5449"
    $a2="4ae6f91928b2a42add6d7628ef395d1b9d66900e8379aca8d778048462cde81cbe53ef595ae7ec64d49b2f0adea1a1fa"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="a741e81d56af5d8d8989246b020b6511ca94eab702c084079afd8a0493d6231f66c3a7ea7a86c37bb61597d4956bb8aa"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}