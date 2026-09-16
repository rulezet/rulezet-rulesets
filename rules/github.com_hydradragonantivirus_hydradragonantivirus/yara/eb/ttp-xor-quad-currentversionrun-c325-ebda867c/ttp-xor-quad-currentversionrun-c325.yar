rule TTP_XOR_QUAD_CurrentVersionRun_c325 {
  strings:
    $key_c325 = { 90 4a [2] b4 44 [2] 9f 68 [2] b1 4a [2] a5 51 [2] aa 4b [2] b4 56 [2] b6 57 [2] ad 51 [2] b1 56 [2] ad 79 }

  condition:
    any of them
}