rule TTP_XOR_QUAD_CurrentVersionRun_c040 {
  strings:
    $key_c040 = { 93 2f [2] b7 21 [2] 9c 0d [2] b2 2f [2] a6 34 [2] a9 2e [2] b7 33 [2] b5 32 [2] ae 34 [2] b2 33 [2] ae 1c }

  condition:
    any of them
}