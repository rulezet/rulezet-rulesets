rule TTP_XOR_QUAD_CurrentVersionRun_d64c {
  strings:
    $key_d64c = { 85 23 [2] a1 2d [2] 8a 01 [2] a4 23 [2] b0 38 [2] bf 22 [2] a1 3f [2] a3 3e [2] b8 38 [2] a4 3f [2] b8 10 }

  condition:
    any of them
}