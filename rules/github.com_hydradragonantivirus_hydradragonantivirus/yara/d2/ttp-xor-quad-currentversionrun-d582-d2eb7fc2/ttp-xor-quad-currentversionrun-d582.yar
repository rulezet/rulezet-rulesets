rule TTP_XOR_QUAD_CurrentVersionRun_d582 {
  strings:
    $key_d582 = { 86 ed [2] a2 e3 [2] 89 cf [2] a7 ed [2] b3 f6 [2] bc ec [2] a2 f1 [2] a0 f0 [2] bb f6 [2] a7 f1 [2] bb de }

  condition:
    any of them
}