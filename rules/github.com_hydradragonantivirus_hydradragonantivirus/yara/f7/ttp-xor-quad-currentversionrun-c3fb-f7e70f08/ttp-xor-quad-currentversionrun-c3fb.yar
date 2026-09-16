rule TTP_XOR_QUAD_CurrentVersionRun_c3fb {
  strings:
    $key_c3fb = { 90 94 [2] b4 9a [2] 9f b6 [2] b1 94 [2] a5 8f [2] aa 95 [2] b4 88 [2] b6 89 [2] ad 8f [2] b1 88 [2] ad a7 }

  condition:
    any of them
}