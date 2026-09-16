rule TTP_XOR_QUAD_CurrentVersionRun_c7eb {
  strings:
    $key_c7eb = { 94 84 [2] b0 8a [2] 9b a6 [2] b5 84 [2] a1 9f [2] ae 85 [2] b0 98 [2] b2 99 [2] a9 9f [2] b5 98 [2] a9 b7 }

  condition:
    any of them
}