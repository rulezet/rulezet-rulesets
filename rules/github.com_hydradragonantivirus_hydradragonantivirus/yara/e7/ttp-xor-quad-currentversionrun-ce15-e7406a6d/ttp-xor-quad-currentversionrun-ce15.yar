rule TTP_XOR_QUAD_CurrentVersionRun_ce15 {
  strings:
    $key_ce15 = { 9d 7a [2] b9 74 [2] 92 58 [2] bc 7a [2] a8 61 [2] a7 7b [2] b9 66 [2] bb 67 [2] a0 61 [2] bc 66 [2] a0 49 }

  condition:
    any of them
}