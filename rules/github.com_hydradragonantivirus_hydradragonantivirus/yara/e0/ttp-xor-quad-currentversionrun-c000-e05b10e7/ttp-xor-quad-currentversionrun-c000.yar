rule TTP_XOR_QUAD_CurrentVersionRun_c000 {
  strings:
    $key_c000 = { 93 6f [2] b7 61 [2] 9c 4d [2] b2 6f [2] a6 74 [2] a9 6e [2] b7 73 [2] b5 72 [2] ae 74 [2] b2 73 [2] ae 5c }

  condition:
    any of them
}