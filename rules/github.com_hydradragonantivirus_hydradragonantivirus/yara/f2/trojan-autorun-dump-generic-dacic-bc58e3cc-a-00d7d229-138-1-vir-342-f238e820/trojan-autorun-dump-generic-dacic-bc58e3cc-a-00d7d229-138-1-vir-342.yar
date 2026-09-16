import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_138_1_Vir_342 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_138_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_406.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_582.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4eafbf53bdb0bb2724ce1d024dc208a96263ff7cee9646a345a80f5923db48c"
    hash2       = "d24945b77013e54246268ee9a7db17b81b7fecc39c29b5c25a32d32c479c499a"
    hash3       = "6c4240bec7c1de831636780540266d9728c221571c8d449cff1aa333405e0f39"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4 = "ptimizer': None, 'optimizer_scheduler': None, 'epochs': 100, 'plus_version': False, 'train_transform': Lambda()}" fullword ascii
    $s5 = "per': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimizatio" ascii
    $s6 = "n_result_': array([0.53206373, 0.12867008, 0.63026328, 0.07853883, 0.3475404 ," fullword ascii
    $s7 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [1.0, 0.999981164932" ascii
    $s8 = "206, 0.999993085861206, 0.999993085861206, 0.999993085861206, 0.999993085861206, 0.999993085861206, 0.999993085861206, 0.9999930" ascii
    $s9 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.9999991655349731," ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "0b36fc85e0cb5e337c80982db5210969" and (all of them)
    ) or (all of them)
}