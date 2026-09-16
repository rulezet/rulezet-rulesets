rule TTP_XOR_QUAD_CurrentVersionRun_c06f {
  strings:
    $key_c06f = { 93 00 [2] b7 0e [2] 9c 22 [2] b2 00 [2] a6 1b [2] a9 01 [2] b7 1c [2] b5 1d [2] ae 1b [2] b2 1c [2] ae 33 }

  condition:
    any of them
}