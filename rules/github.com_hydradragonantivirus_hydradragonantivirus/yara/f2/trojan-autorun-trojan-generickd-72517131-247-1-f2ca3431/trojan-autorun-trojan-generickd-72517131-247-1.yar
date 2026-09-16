rule Trojan_Autorun_Trojan_GenericKD_72517131_247_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_247_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9ad2d0e2af33fa6a1e95eaf327fcfa5ef1c7e4395a1c39bc694935ac89ee7b2"

  strings:
    $s1  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s5  = "ions_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debu" ascii
    $s6  = "g': False, 'minimization_result_" fullword ascii
    $s7  = " None, 'n_jobs':" fullword ascii
    $s8  = "ckbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii
    $s9  = "g': False, 'minimization_result_': array([0.50197491, 0.06934716, 0.16838985, 0.02521312, 0.99351002," fullword ascii
    $s10 = "ptimizer': None, 'optim" fullword ascii
    $s11 = "978149, 0.9999986886978149, 0.9999986886978149, 0.9999986886978149, 0.9999986886978149, 0.9999986886978149, 0.9999986886978149, " ascii
    $s12 = "82747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 282747, 2" ascii
    $s13 = "object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': " fullword ascii
    $s14 = "CGeneticAlgorithm{'classifier': CClassifierEnd2EndMalware{'classes': array([0, 1]), 'n_features'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}