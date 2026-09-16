rule TTP_XOR_QUAD_CurrentVersionRun_c01d {
  strings:
    $key_c01d = { 93 72 [2] b7 7c [2] 9c 50 [2] b2 72 [2] a6 69 [2] a9 73 [2] b7 6e [2] b5 6f [2] ae 69 [2] b2 6e [2] ae 41 }

  condition:
    any of them
}