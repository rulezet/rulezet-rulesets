rule TTP_XOR_QUAD_CurrentVersionRun_d268 {
  strings:
    $key_d268 = { 81 07 [2] a5 09 [2] 8e 25 [2] a0 07 [2] b4 1c [2] bb 06 [2] a5 1b [2] a7 1a [2] bc 1c [2] a0 1b [2] bc 34 }

  condition:
    any of them
}