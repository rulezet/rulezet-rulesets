rule sha3_384_hashed_default_creds_schneider
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schneider."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4edb2be26a95dd2a52b2a7445cfbfc952a6b5fda84c264675a762a194af78b28d58fcc87f2edab6732589a8daa22684b"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="0723ac2e44eff4e98485856446f8d3be0c882ae75d96590bd5f0eea00e1c3880ee0886b203466a4d6ca31ef912ca5d10"
    $a3="3ddeb8b95dd2315b7936faac32bc6de74912185774399efaad2664e1c51468feec3fb41f11be45fea2a3d3f936d24590"
    $a4="150706009491b4d06ae288d433d9c44447986c822b13953dad1ac43a8c5bba91d0d676b9049bb1c2f118a910def71113"
    $a5="5431a842fbe7eb8e68f25ee6193aedc5a7ed098cc5087a760f578bffa4e9130c5d58a71cb47c526062eb1e73f5563c11"
    $a6="709e2079fbc4c09162c2751ed9c769319893ea72a7a57a28ea69b061df3729172c2f5cace165043002db069f7a87d552"
    $a7="0cb2b82d10f9706e6bf686dd25610eb3c35c3f8a02fc6908be29483d0204f19fc8d802cc4b296f86f3e5a8c3fe5627ed"
    $a8="1982f42589842b2044a81748873969acbc6ab0b28305259651b29c6a3dbe9e17515dd60ea81dd506ad0a6df96e048726"
    $a9="46d4665406a2b67de50adfa819779a33d776eb80884c016b31f2d9d12bc3f584f8d1ad18f9da4efd4618b6f18dd6ebdd"
    $a10="87a06473be4a29ab2c863ea66d53a06fa9d6883ee4fe301567bef102479fa7749cdcee7933ac0f8e61f3d1326a68e07c"
    $a11="87a06473be4a29ab2c863ea66d53a06fa9d6883ee4fe301567bef102479fa7749cdcee7933ac0f8e61f3d1326a68e07c"
    $a12="b45644a05028971ab803d1c69a1d8b6f567c63312ec45d172d35ea5e0ae530f800d17a7e84dd737add8ef93e794fff9f"
    $a13="87a06473be4a29ab2c863ea66d53a06fa9d6883ee4fe301567bef102479fa7749cdcee7933ac0f8e61f3d1326a68e07c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}