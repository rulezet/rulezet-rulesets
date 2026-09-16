rule TTP_XOR_QUAD_CurrentVersionRun_dffb {
  strings:
    $key_dffb = { 8c 94 [2] a8 9a [2] 83 b6 [2] ad 94 [2] b9 8f [2] b6 95 [2] a8 88 [2] aa 89 [2] b1 8f [2] ad 88 [2] b1 a7 }

  condition:
    any of them
}