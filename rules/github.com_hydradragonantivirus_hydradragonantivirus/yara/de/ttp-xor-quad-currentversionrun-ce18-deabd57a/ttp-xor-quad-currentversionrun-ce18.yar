rule TTP_XOR_QUAD_CurrentVersionRun_ce18 {
  strings:
    $key_ce18 = { 9d 77 [2] b9 79 [2] 92 55 [2] bc 77 [2] a8 6c [2] a7 76 [2] b9 6b [2] bb 6a [2] a0 6c [2] bc 6b [2] a0 44 }

  condition:
    any of them
}