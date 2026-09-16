rule TTP_XOR_QUAD_CurrentVersionRun_d15e {
  strings:
    $key_d15e = { 82 31 [2] a6 3f [2] 8d 13 [2] a3 31 [2] b7 2a [2] b8 30 [2] a6 2d [2] a4 2c [2] bf 2a [2] a3 2d [2] bf 02 }

  condition:
    any of them
}