rule TTP_XOR_QUAD_CurrentVersionRun_c309 {
  strings:
    $key_c309 = { 90 66 [2] b4 68 [2] 9f 44 [2] b1 66 [2] a5 7d [2] aa 67 [2] b4 7a [2] b6 7b [2] ad 7d [2] b1 7a [2] ad 55 }

  condition:
    any of them
}