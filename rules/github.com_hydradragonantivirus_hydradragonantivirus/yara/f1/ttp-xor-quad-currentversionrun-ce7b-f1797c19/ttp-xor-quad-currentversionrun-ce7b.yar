rule TTP_XOR_QUAD_CurrentVersionRun_ce7b {
  strings:
    $key_ce7b = { 9d 14 [2] b9 1a [2] 92 36 [2] bc 14 [2] a8 0f [2] a7 15 [2] b9 08 [2] bb 09 [2] a0 0f [2] bc 08 [2] a0 27 }

  condition:
    any of them
}