rule sha3_384_hashed_default_creds_db2_db2
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for db2_db2."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e9eb23a06d38bd2cdf54509a7a62270886c22f3aed98d4173ce790dbb760cf39449a57725192b88e7dc0918a431c8f0"
    $a1="2f7d31ca9dd025b43c49b6c2c347bf9224d2149e59d34cbcb305a6961223345fcf422da45d4a066f034b0f144c64d237"
    $a2="860a04daa7d631ec9457f8a6774796410a52b66fa59e518f7d65723bd2efa93bfafaf09b85262b0053569815080e7eb0"
    $a3="860a04daa7d631ec9457f8a6774796410a52b66fa59e518f7d65723bd2efa93bfafaf09b85262b0053569815080e7eb0"
    $a4="f132684a4eaa1f3eb9b14be791c892cde5090361ac8b15168c7057ca8a44fab8a9f910e9f971cf1942fae573f396f6cb"
    $a5="f132684a4eaa1f3eb9b14be791c892cde5090361ac8b15168c7057ca8a44fab8a9f910e9f971cf1942fae573f396f6cb"
    $a6="046267a387db0d417a3770efc35e6a2f256ad654e68c8758069825389347a009561ba37d8df56b1bb3c03dd7e10387ba"
    $a7="046267a387db0d417a3770efc35e6a2f256ad654e68c8758069825389347a009561ba37d8df56b1bb3c03dd7e10387ba"
    $a8="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a9="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a10="84ae223476e3cfa04664ba722ced9673201ad952c54dca643e2232e53a84dd0de10e1f39ea224992c7ed899158d06782"
    $a11="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a12="f3798844891b25382185c34712f3b59771cfbb2dac1b84c874dba99ad36426b9410064af83fdc1694b332cbbeead3f79"
    $a13="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
    $a14="a182187162d7333ad05857b12b760c9683fc10bbc2fe1ad9ea982e1473ba668b1c6e0d55e21db8b7ca53c0d9c6556bab"
    $a15="2cca32621269bbc6f9a333d183a29030e8612fd91a4a7a21aa55fd19b9927d6c28dc88937f5fca722d479ce8ef349354"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13) or ($a14 and $a15)
}