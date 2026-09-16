rule TTP_XOR_QUAD_CurrentVersionRun_d660 {
  strings:
    $key_d660 = { 85 0f [2] a1 01 [2] 8a 2d [2] a4 0f [2] b0 14 [2] bf 0e [2] a1 13 [2] a3 12 [2] b8 14 [2] a4 13 [2] b8 3c }

  condition:
    any of them
}