rule TTP_XOR_QUAD_CurrentVersionRun_c770 {
  strings:
    $key_c770 = { 94 1f [2] b0 11 [2] 9b 3d [2] b5 1f [2] a1 04 [2] ae 1e [2] b0 03 [2] b2 02 [2] a9 04 [2] b5 03 [2] a9 2c }

  condition:
    any of them
}