rule TTP_XOR_QUAD_CurrentVersionRun_c16e {
  strings:
    $key_c16e = { 92 01 [2] b6 0f [2] 9d 23 [2] b3 01 [2] a7 1a [2] a8 00 [2] b6 1d [2] b4 1c [2] af 1a [2] b3 1d [2] af 32 }

  condition:
    any of them
}