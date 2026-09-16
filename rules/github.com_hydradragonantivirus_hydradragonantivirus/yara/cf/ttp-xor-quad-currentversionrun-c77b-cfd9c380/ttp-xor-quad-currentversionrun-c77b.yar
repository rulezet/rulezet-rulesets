rule TTP_XOR_QUAD_CurrentVersionRun_c77b {
  strings:
    $key_c77b = { 94 14 [2] b0 1a [2] 9b 36 [2] b5 14 [2] a1 0f [2] ae 15 [2] b0 08 [2] b2 09 [2] a9 0f [2] b5 08 [2] a9 27 }

  condition:
    any of them
}