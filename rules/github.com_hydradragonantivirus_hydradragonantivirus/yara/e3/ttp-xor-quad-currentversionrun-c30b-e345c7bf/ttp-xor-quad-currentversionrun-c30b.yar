rule TTP_XOR_QUAD_CurrentVersionRun_c30b {
  strings:
    $key_c30b = { 90 64 [2] b4 6a [2] 9f 46 [2] b1 64 [2] a5 7f [2] aa 65 [2] b4 78 [2] b6 79 [2] ad 7f [2] b1 78 [2] ad 57 }

  condition:
    any of them
}