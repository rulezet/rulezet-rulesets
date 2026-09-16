rule TTP_XOR_QUAD_CurrentVersionRun_d60b {
  strings:
    $key_d60b = { 85 64 [2] a1 6a [2] 8a 46 [2] a4 64 [2] b0 7f [2] bf 65 [2] a1 78 [2] a3 79 [2] b8 7f [2] a4 78 [2] b8 57 }

  condition:
    any of them
}