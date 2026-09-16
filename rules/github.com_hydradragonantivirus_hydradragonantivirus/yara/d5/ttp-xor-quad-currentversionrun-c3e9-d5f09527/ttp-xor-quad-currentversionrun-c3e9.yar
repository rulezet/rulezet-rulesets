rule TTP_XOR_QUAD_CurrentVersionRun_c3e9 {
  strings:
    $key_c3e9 = { 90 86 [2] b4 88 [2] 9f a4 [2] b1 86 [2] a5 9d [2] aa 87 [2] b4 9a [2] b6 9b [2] ad 9d [2] b1 9a [2] ad b5 }

  condition:
    any of them
}