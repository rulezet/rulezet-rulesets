rule TTP_XOR_QUAD_CurrentVersionRun_d17a {
  strings:
    $key_d17a = { 82 15 [2] a6 1b [2] 8d 37 [2] a3 15 [2] b7 0e [2] b8 14 [2] a6 09 [2] a4 08 [2] bf 0e [2] a3 09 [2] bf 26 }

  condition:
    any of them
}