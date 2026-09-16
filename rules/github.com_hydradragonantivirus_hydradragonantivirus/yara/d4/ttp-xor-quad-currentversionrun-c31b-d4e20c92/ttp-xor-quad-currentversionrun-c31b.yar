rule TTP_XOR_QUAD_CurrentVersionRun_c31b {
  strings:
    $key_c31b = { 90 74 [2] b4 7a [2] 9f 56 [2] b1 74 [2] a5 6f [2] aa 75 [2] b4 68 [2] b6 69 [2] ad 6f [2] b1 68 [2] ad 47 }

  condition:
    any of them
}