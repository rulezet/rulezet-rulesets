rule sha3_384_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5eaff866446a84bcf1842a8fd1c991f9d17c927faf304b6483e8f6d659d63658cf7d864539de4ee97eda9765074b7357"
    $a1="c7bd3a0bb0cdc72a7f6e39a620ea6ed9cbace0d27d492ad577464919bf3be64d35fd4caeea95a71215d52da7fe376be5"
    $a2="f2ca92747c0723e835ce642f6a0d11d7d070670627304d66509e1f45430e9260c625b5784d62bbc9c35856394efb4861"
    $a3="dc33ecf079ab601fb3efeee56e49b810ef8400431056aaf8bb909495e7d89870b271b7f842455a4bdac5806670dcd58d"
    $a4="6be7b773a88d446849a5f562ad58f056468fce2e2e03f025e9f1c3512c4989db1a9be7990ed7462f7c7fabf959694843"
    $a5="855529acb5d476167205f6f7f4ba398d07d5e1efa6043e0c23006ddddd616493dad03cb088a1d2cda10096c26ecf41cc"
    $a6="fa51e254e7829ca1759a5e93d38d537f6935af5ec8e0f123f5872f1e203b414e96c63488a0be5b7fbab55529ce016794"
    $a7="02443e35a14c848f5a97fe4ea146071b8089f14fa253d80ce4850ad6910cb16f56976cbd30568256062833508ca32b88"
    $a8="4a7423a1ab3019f8b382a77b81225edbece3a3f22e5e52778e5f9396593bc9f261cbafde9200823468d6ea9559408e77"
    $a9="4bd853ec48990a0b919317762054e7e4a333abcdef6c5b3b28e23487f77e545d9afb58c07937d7a7c45ea4c2841dce67"
    $a10="bff3c4aab81c8b6c7544ab72666eadae5e991761d5e69640ce1cb6039354180159d4ad0ecbc20b1e62c79ba98f2247d3"
    $a11="8648e91e15bd6cfca27c29475f37b560587eea33e4cd89cc1f8329e72f735908b783e5a857c963c3b6a231972baaa11d"
    $a12="2fbdf8834a92a034434c2614ab2c99d7844668f908abd75c135178dbaacf069600ab67d7b257ae19e438117ee28591f9"
    $a13="13cdfc300d59dd907b2da20cafd595ac1b169dd0ecbc70108c75738c8ae6e2cd8f34a6bf4461a05e3520c199fd23184b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}