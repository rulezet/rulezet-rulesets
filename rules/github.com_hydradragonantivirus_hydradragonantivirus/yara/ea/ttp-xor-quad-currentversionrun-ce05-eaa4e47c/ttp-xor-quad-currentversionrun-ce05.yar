rule TTP_XOR_QUAD_CurrentVersionRun_ce05 {
  strings:
    $key_ce05 = { 9d 6a [2] b9 64 [2] 92 48 [2] bc 6a [2] a8 71 [2] a7 6b [2] b9 76 [2] bb 77 [2] a0 71 [2] bc 76 [2] a0 59 }

  condition:
    any of them
}