rule TTP_XOR_QUAD_CurrentVersionRun_c04c {
  strings:
    $key_c04c = { 93 23 [2] b7 2d [2] 9c 01 [2] b2 23 [2] a6 38 [2] a9 22 [2] b7 3f [2] b5 3e [2] ae 38 [2] b2 3f [2] ae 10 }

  condition:
    any of them
}