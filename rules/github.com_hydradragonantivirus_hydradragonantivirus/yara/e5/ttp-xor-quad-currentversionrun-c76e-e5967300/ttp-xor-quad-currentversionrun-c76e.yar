rule TTP_XOR_QUAD_CurrentVersionRun_c76e {
  strings:
    $key_c76e = { 94 01 [2] b0 0f [2] 9b 23 [2] b5 01 [2] a1 1a [2] ae 00 [2] b0 1d [2] b2 1c [2] a9 1a [2] b5 1d [2] a9 32 }

  condition:
    any of them
}