rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_473_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_473_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8226a840dc19967f9a9050b0e0d90e1b3c01f7fa9d6c142ddfcb2a0215eb91d3"

  strings:
    $s1 = "<secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}