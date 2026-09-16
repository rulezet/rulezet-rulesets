rule TTP_XOR_QUAD_CurrentVersionRun_c3fa {
  strings:
    $key_c3fa = { 90 95 [2] b4 9b [2] 9f b7 [2] b1 95 [2] a5 8e [2] aa 94 [2] b4 89 [2] b6 88 [2] ad 8e [2] b1 89 [2] ad a6 }

  condition:
    any of them
}