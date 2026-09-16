rule TTP_XOR_QUAD_CurrentVersionRun_c060 {
  strings:
    $key_c060 = { 93 0f [2] b7 01 [2] 9c 2d [2] b2 0f [2] a6 14 [2] a9 0e [2] b7 13 [2] b5 12 [2] ae 14 [2] b2 13 [2] ae 3c }

  condition:
    any of them
}