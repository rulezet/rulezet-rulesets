rule TTP_XOR_QUAD_CurrentVersionRun_ce29 {
  strings:
    $key_ce29 = { 9d 46 [2] b9 48 [2] 92 64 [2] bc 46 [2] a8 5d [2] a7 47 [2] b9 5a [2] bb 5b [2] a0 5d [2] bc 5a [2] a0 75 }

  condition:
    any of them
}