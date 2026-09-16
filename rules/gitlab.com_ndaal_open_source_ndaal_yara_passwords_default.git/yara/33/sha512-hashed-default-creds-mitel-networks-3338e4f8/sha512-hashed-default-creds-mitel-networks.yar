rule sha512_hashed_default_creds_mitel_networks
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mitel_networks."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e6d06f0f0f0474e5c1e035b32fa569afcdd11fe76240ef2e4ee04cf8dc694b7f2a716f513e2c351feed667633901c8cf6e66ec24e75f270f6b8a6e3c903dd8b"
    $a1="e81ed1691a06474a55642a2fd13ed615db96e349586bd2809f9156ff44c4935bf7fe00b4f113184fcbdf73e3da7fe49f970e62f38ea9524f05addad05a1705e6"
    $a2="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a3="b77fe2d86fbc5bd116d6a073eb447e76a74add3fa0d0b801f97535963241be3cdce1dbcaed603b78f020d0845b2d4bfc892ceb2a7d1c8f1d98abc4812ef5af21"
    $a4="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a5="b398d0ea5ece18bdb119da542f71abfbe1eb1472f577f9d684cc169da4ac7724e96cc19ba11f70817f25eb33e5d920da194bca51b4c996253159c03bc92ca50d"
    $a6="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a7="8cffcc26d16dff5fd03e89b5eaca435998535a3730f8187b6341b44162590330119f5812316523dfad29cbff26a1ab1f5475509b95f05a61b737dd663866317e"
    $a8="1e6d06f0f0f0474e5c1e035b32fa569afcdd11fe76240ef2e4ee04cf8dc694b7f2a716f513e2c351feed667633901c8cf6e66ec24e75f270f6b8a6e3c903dd8b"
    $a9="2cc595c5b93f860d70a9a6706d24ffc28954fb5b5ac98a5a1fb996e212375db4080315ba73850e7ffdc0c8d181b8a3a04ebe9383d8f7ed41f57014628e315ee8"
    $a10="b54d41342bdd4bae48b2c596315046e55a7d774701f98c8a7ba93edb8cc48ebea557d4d6eff0af7b594161dce9ed99d96d760a73bf4db54e81d63b30880b56b6"
    $a11="59a94a0ac0f75200d1477d0f158a23d7feb08a2db16d21233b36fc8fda1a958c1be52b439f7957733bd65950cdfa7918b2f76a480ed01bb6e4edf4614eb8a708"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}