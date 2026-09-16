rule TTP_XOR_QUAD_CurrentVersionRun_c72b {
  strings:
    $key_c72b = { 94 44 [2] b0 4a [2] 9b 66 [2] b5 44 [2] a1 5f [2] ae 45 [2] b0 58 [2] b2 59 [2] a9 5f [2] b5 58 [2] a9 77 }

  condition:
    any of them
}