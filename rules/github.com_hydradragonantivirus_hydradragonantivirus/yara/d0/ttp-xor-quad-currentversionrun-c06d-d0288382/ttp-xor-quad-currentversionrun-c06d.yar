rule TTP_XOR_QUAD_CurrentVersionRun_c06d {
  strings:
    $key_c06d = { 93 02 [2] b7 0c [2] 9c 20 [2] b2 02 [2] a6 19 [2] a9 03 [2] b7 1e [2] b5 1f [2] ae 19 [2] b2 1e [2] ae 31 }

  condition:
    any of them
}