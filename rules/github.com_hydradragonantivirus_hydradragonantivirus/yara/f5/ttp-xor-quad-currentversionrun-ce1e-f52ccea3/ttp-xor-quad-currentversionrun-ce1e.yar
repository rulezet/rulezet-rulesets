rule TTP_XOR_QUAD_CurrentVersionRun_ce1e {
  strings:
    $key_ce1e = { 9d 71 [2] b9 7f [2] 92 53 [2] bc 71 [2] a8 6a [2] a7 70 [2] b9 6d [2] bb 6c [2] a0 6a [2] bc 6d [2] a0 42 }

  condition:
    any of them
}