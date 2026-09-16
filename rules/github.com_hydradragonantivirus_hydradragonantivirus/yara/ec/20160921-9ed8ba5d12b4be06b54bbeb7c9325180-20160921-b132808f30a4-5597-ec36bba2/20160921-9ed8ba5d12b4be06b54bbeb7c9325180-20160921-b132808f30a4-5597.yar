rule _20160921_9ed8ba5d12b4be06b54bbeb7c9325180_20160921_b132808f30a4_5597 {
  meta:
    description = "datamaliciousorder - from files 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_b132808f30a4f3b5c484e9734dc93fcc.js, 20160921_e1c974d7750547ace34afdda5a06de15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash2       = "03f070dd06dae48f7c253ddc9a238e441aaac22f9de6e238ba5d3ffa0b9220b4"
    hash3       = "bed4e8c71e09f1ca8c800564bc43d4e103353ec558d1f0869c85d3e8f8c43b01"

  strings:
    $s1 = " f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QD" ascii
    $s2 = "ion f000(){return \"QDg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return " ascii
    $s3 = "on f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"" ascii
    $s4 = "urn \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DAp\";})()," ascii
    $s5 = "n f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}