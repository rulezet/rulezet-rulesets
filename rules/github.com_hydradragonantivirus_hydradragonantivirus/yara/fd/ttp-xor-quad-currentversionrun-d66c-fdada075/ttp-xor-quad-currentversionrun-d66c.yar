rule TTP_XOR_QUAD_CurrentVersionRun_d66c {
  strings:
    $key_d66c = { 85 03 [2] a1 0d [2] 8a 21 [2] a4 03 [2] b0 18 [2] bf 02 [2] a1 1f [2] a3 1e [2] b8 18 [2] a4 1f [2] b8 30 }

  condition:
    any of them
}