rule sha3_512_hashed_default_creds_clearone_communications
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for clearone_communications."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1ecc7b00ffa23befbe039e9ff3fa24459803b76ceee959e764ea5f91ec0ba79ecbbf1885fea69c70be9df66cf7b0a95fc76716a18ec629902c150c36edf2f1ec"
    $a1="4b8192c5ec7975664d009ee684cebdf44c7b33d106699b5d94762f17673e64ae3203441666c418fb16b75317c529b43c4aa3cadea14152864b45cb7c9c5fc76f"
    $a2="08aca657e4b9e6a400041464ca90dd090e4c945645c7995879da851cc75c3dfc188646ac0049a732ab52f39219029ea97a369c6ba3cfaded679e159d5a609d11"
    $a3="2917ab1e249787255701b6c3852cecda12dfebb8bb1160d4dcaf420de2b43c7baaf2c6c91a4507e8f506f5fed262dbe218dadb9d56b136aef439ffb546cbf20f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}