rule TTP_XOR_QUAD_CurrentVersionRun_ce02 {
  strings:
    $key_ce02 = { 9d 6d [2] b9 63 [2] 92 4f [2] bc 6d [2] a8 76 [2] a7 6c [2] b9 71 [2] bb 70 [2] a0 76 [2] bc 71 [2] a0 5e }

  condition:
    any of them
}