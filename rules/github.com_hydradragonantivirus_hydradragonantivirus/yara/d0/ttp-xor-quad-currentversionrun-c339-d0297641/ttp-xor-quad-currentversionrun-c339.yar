rule TTP_XOR_QUAD_CurrentVersionRun_c339 {
  strings:
    $key_c339 = { 90 56 [2] b4 58 [2] 9f 74 [2] b1 56 [2] a5 4d [2] aa 57 [2] b4 4a [2] b6 4b [2] ad 4d [2] b1 4a [2] ad 65 }

  condition:
    any of them
}