rule blake2s_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cadc299bc63226370ced068e55acb4b9327e67aee8f3d73d43029966550c6c26"
    $a1="0c5f0e9680df8844e5bd9837df1646101ff36ae4c38bd26b0843581694587c26"
    $a2="a816efc212cc2184870ec5fc4bc758038a0c0971ab17d651c3452c3a5f01a350"
    $a3="bfe09a792e7c4f685b48f7d0e7246242d4453e032c305fd01a6dd148637f83ed"
    $a4="2c646d78f1e332423b98a4c004c001bc9880f2711e8788173709b2ec7b7e457c"
    $a5="332266bbb621eb4f0c252f9bc43a739aab0fcde2fce3f9d139b8a80115811c6f"
    $a6="28ecec77d325554e7dc0fc33b5206ffe2e740c028ba0de634491112ce41fa67b"
    $a7="ed26be2b4a908bb9b6b223c524f029f4056a7eacd888858be06095ca8a7a158c"
    $a8="afadfd6aeacbdb5b4fd6ba8badc6dc3b844e5689c6512f6d976939cbfdb39a43"
    $a9="99cc0856147014aeece860b216ac3e742a92660e84331ba29c90352f1d24dc80"
    $a10="1e53810f203f5c01555ebf7d3d838b247ee9b228d5779260b6449245adafed16"
    $a11="451c66440f6521a19cb273ae33a49ffd0e8f3f9919cf58259ed3a91ae67a5a48"
    $a12="b0ef5b598882fd0bb65ec66cd62b4a62d95389bfd9688723f7550feaa21be1f7"
    $a13="7f021dfcdf4ef08cd017340bf199b31ea6d62998508bf693742fda607171e857"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}