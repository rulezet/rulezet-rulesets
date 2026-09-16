rule Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58e48308422b7e1faa427a4cd94bb5ed6d5933cc64ff88e1f643b91d036ca508"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "apper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0.80998861, 0.02506225" ascii
    $s3 = "  (dense_2): Linear(in_features=128, out_features=1, bias=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}