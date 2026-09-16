rule TTP_XOR_QUAD_CurrentVersionRun_d140 {
  strings:
    $key_d140 = { 82 2f [2] a6 21 [2] 8d 0d [2] a3 2f [2] b7 34 [2] b8 2e [2] a6 33 [2] a4 32 [2] bf 34 [2] a3 33 [2] bf 1c }

  condition:
    any of them
}