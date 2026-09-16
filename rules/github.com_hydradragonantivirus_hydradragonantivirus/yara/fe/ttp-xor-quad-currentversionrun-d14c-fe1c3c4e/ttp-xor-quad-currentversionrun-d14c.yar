rule TTP_XOR_QUAD_CurrentVersionRun_d14c {
  strings:
    $key_d14c = { 82 23 [2] a6 2d [2] 8d 01 [2] a3 23 [2] b7 38 [2] b8 22 [2] a6 3f [2] a4 3e [2] bf 38 [2] a3 3f [2] bf 10 }

  condition:
    any of them
}