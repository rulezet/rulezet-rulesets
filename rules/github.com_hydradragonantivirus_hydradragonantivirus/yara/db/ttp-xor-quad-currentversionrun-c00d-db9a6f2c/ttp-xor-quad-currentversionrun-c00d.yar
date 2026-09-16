rule TTP_XOR_QUAD_CurrentVersionRun_c00d {
  strings:
    $key_c00d = { 93 62 [2] b7 6c [2] 9c 40 [2] b2 62 [2] a6 79 [2] a9 63 [2] b7 7e [2] b5 7f [2] ae 79 [2] b2 7e [2] ae 51 }

  condition:
    any of them
}