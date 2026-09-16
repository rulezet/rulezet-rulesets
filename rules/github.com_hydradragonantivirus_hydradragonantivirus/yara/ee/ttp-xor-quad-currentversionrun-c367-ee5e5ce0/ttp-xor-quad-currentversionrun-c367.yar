rule TTP_XOR_QUAD_CurrentVersionRun_c367 {
  strings:
    $key_c367 = { 90 08 [2] b4 06 [2] 9f 2a [2] b1 08 [2] a5 13 [2] aa 09 [2] b4 14 [2] b6 15 [2] ad 13 [2] b1 14 [2] ad 3b }

  condition:
    any of them
}