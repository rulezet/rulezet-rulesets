rule TTP_XOR_QUAD_CurrentVersionRun_c347 {
  strings:
    $key_c347 = { 90 28 [2] b4 26 [2] 9f 0a [2] b1 28 [2] a5 33 [2] aa 29 [2] b4 34 [2] b6 35 [2] ad 33 [2] b1 34 [2] ad 1b }

  condition:
    any of them
}