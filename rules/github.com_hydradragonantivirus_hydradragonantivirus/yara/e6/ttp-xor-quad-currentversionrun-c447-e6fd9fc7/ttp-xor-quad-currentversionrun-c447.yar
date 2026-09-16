rule TTP_XOR_QUAD_CurrentVersionRun_c447 {
  strings:
    $key_c447 = { 97 28 [2] b3 26 [2] 98 0a [2] b6 28 [2] a2 33 [2] ad 29 [2] b3 34 [2] b1 35 [2] aa 33 [2] b6 34 [2] aa 1b }

  condition:
    any of them
}