rule TTP_XOR_QUAD_CurrentVersionRun_d17e {
  strings:
    $key_d17e = { 82 11 [2] a6 1f [2] 8d 33 [2] a3 11 [2] b7 0a [2] b8 10 [2] a6 0d [2] a4 0c [2] bf 0a [2] a3 0d [2] bf 22 }

  condition:
    any of them
}