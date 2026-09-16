rule TTP_XOR_QUAD_CurrentVersionRun_d538 {
  strings:
    $key_d538 = { 86 57 [2] a2 59 [2] 89 75 [2] a7 57 [2] b3 4c [2] bc 56 [2] a2 4b [2] a0 4a [2] bb 4c [2] a7 4b [2] bb 64 }

  condition:
    any of them
}