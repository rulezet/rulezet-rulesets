rule TTP_XOR_QUAD_CurrentVersionRun_ce4e {
  strings:
    $key_ce4e = { 9d 21 [2] b9 2f [2] 92 03 [2] bc 21 [2] a8 3a [2] a7 20 [2] b9 3d [2] bb 3c [2] a0 3a [2] bc 3d [2] a0 12 }

  condition:
    any of them
}