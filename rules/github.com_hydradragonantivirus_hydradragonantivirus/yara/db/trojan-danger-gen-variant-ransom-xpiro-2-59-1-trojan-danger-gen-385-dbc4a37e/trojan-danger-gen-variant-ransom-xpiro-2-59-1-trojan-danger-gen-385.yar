import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_59_1_Trojan_Danger_Gen_385 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_59_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_68_1.vir, Trojan.Danger_Generic.Dacic.1A7FA519.A.ED54282A_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.BuZ@amBwvTb.vir, Virus.Hijack_Gen.Trojan.ShellObject.BuZ@amBwvTb_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.BuZ@amBwvTb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "386e55723ad6fd477a18441d7d58f35c9936eb28f075c7936cf679ac00c3ce4e"
    hash2       = "3480ba5d4900b0c9e8b5997c281ca25a3a1622bdeb1ce5a2c83a239f0be7b48f"
    hash3       = "7e499a433ad4d8cd5005a46b12d4b71a23a79e9659d3037b9c95092be8a4367e"
    hash4       = "94500dd76d45d5b4402c88c4c73670cf6e3a725492de4119212023d34c5d287a"
    hash5       = "6fb217c3caf88cc88c24af939945cc359807a3c1cbb2e23f78e0c888642b0ab1"
    hash6       = "c6a068af685ac45b34a66091b2b9968bcc0dbcb60ed8156d3d0f9fa0a1818b92"

  strings:
    $s1  = "Point: 0/1, f(x):0.11511683464050293, eval:<bound method CGeneticAlgorithm.f_eval of CGeneticAlgorithm{'classifier': CClassifier" ascii
    $s2  = "End2EndMalware{'classes': array([0, 1]), 'n_features': 1048576, 'preprocess': None, 'n_jobs': 1, 'model': MalConv(" fullword ascii
    $s3  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s4  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s5  = "malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': a" ascii
    $s6  = "near(in_features=128, out_features=128, bias=True)" fullword ascii
    $s7  = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [0.5356553196907043," ascii
    $s8  = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256,>" fullword ascii
    $s9  = " 'f_opt': None, 'x_seq VW" fullword ascii
    $s10 = "Point: 0/1, f(x):0.11511683464050293, eval:<bound method CGeneticAlgorithm.f_eval of CGeneticAlgorithm{'classifier': CClassifier" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26babd76bbb7f9c516a338b0601b4c9f" and (all of them)
    ) or (all of them)
}