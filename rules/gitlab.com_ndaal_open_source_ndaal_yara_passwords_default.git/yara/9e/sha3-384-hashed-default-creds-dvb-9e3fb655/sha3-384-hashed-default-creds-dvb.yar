rule sha3_384_hashed_default_creds_dvb
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for dvb."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cb706c3e31df148cc49564c39065f6f88d1414a31ba9e682fd7cb36509d06dccd3c7b6036d08ad4c23ac59ca13b05c40"
    $a1="3a33307afd768c1c5a32081b38e6ac2b2f10453c27f60802cd9088374eec4bff7abc227e9418242653f4a6e8d632b8c0"
    $a2="88c3f3ba017c5ed9cfac15e6ac246719d23396bb7b0e7cb1ea8b8412acaa4e37b5e034eff76755231de977c153f8d052"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}