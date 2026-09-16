rule TTP_XOR_QUAD_CurrentVersionRun_c71b {
  strings:
    $key_c71b = { 94 74 [2] b0 7a [2] 9b 56 [2] b5 74 [2] a1 6f [2] ae 75 [2] b0 68 [2] b2 69 [2] a9 6f [2] b5 68 [2] a9 47 }

  condition:
    any of them
}