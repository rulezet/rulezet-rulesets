rule TTP_XOR_QUAD_CurrentVersionRun_c05f {
  strings:
    $key_c05f = { 93 30 [2] b7 3e [2] 9c 12 [2] b2 30 [2] a6 2b [2] a9 31 [2] b7 2c [2] b5 2d [2] ae 2b [2] b2 2c [2] ae 03 }

  condition:
    any of them
}