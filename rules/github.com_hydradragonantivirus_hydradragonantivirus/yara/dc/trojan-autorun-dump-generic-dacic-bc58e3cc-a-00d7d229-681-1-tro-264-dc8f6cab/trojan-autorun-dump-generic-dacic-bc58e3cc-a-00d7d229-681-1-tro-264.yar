import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_681_1_Tro_264 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_681_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_78_1.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_84_1.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_12.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_136.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_346.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_418.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_455.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_53.vir, Virus.Hijack_GenPack.Backdoor.Hangup.B_79.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0626a50943f9dd5cd6263c263182c0203fadd721b499260e8dc9bdf1a91fcfa5"
    hash2       = "48d06a02bc371fa56790971c9ec0b245db919cdfb1ee86f4a7df17c77f6dea04"
    hash3       = "1e28d9939c19899e18026797b774ede125340d70cd5e585d6c49926d48b67f9d"
    hash4       = "29859d2c4d098b0c50f579ed72cec6d7c4e7d5dd2752609655df273c0666dfe8"
    hash5       = "e9babba397eef77ca27ab0bc3ff5b07fc84a461aaaaa8912e429aa28525dde74"
    hash6       = "23eb08b0f9e38ca63709717917a65d7226fe6d4794151e0245d059d79790271c"
    hash7       = "36db82105cc95df5bc58c531732a1a70bbdcd320de447dcc58e0be76564919c5"
    hash8       = "05592497597b5bbd8372d7dca583c931d87339b09a2f76c7c373c499be44ac7c"
    hash9       = "cd0c08353fa32d409ac526a4d61a5f6ecabd5c77e65e571cb13bf1e5e5b9c98c"
    hash10      = "76becbef2433037bc0c8c17fddae4f9431ffeaf72a336bd1f54362a053880416"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s3 = "anges_per_iterations_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08e" ascii
    $s4 = ", 'is_debug': False, 'minimization_result_': array([0.79851747, 0.14893367, 0.12060458, 0.07588433, 0.1211008 ," fullword ascii
    $s5 = "random0.005001774523407221, 0.005001774523407221, 0.005001774523407221, 0.005001774523407221, 0.005001774523407221, 0.0050017745" ascii
    $s6 = "cml_malware.attack.blackbox.c_gamma_evasion.CGammaEvasionProblem object at 0x7f5c08e9a040>, 'confidences_': [1.0, 0.999960780143" ascii
    $s7 = "bedding(257, " fullword ascii
    $s8 = "c3d00>, 'is_debug': False, 'minimization_result_': array([0.66070571, 0.06128269, 0.08587467, 0.10519434, 0.94684678," fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "95e6f8741083e0c7d9a63d45e2472360" and (all of them)
    ) or (all of them)
}