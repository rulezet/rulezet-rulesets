rule TTP_XOR_QUAD_CurrentVersionRun_c315 {
  strings:
    $key_c315 = { 90 7a [2] b4 74 [2] 9f 58 [2] b1 7a [2] a5 61 [2] aa 7b [2] b4 66 [2] b6 67 [2] ad 61 [2] b1 66 [2] ad 49 }

  condition:
    any of them
}