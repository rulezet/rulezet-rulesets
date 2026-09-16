rule TTP_XOR_QUAD_CurrentVersionRun_c00c {
  strings:
    $key_c00c = { 93 63 [2] b7 6d [2] 9c 41 [2] b2 63 [2] a6 78 [2] a9 62 [2] b7 7f [2] b5 7e [2] ae 78 [2] b2 7f [2] ae 50 }

  condition:
    any of them
}