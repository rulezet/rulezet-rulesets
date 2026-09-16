rule TTP_XOR_QUAD_CurrentVersionRun_c750 {
  strings:
    $key_c750 = { 94 3f [2] b0 31 [2] 9b 1d [2] b5 3f [2] a1 24 [2] ae 3e [2] b0 23 [2] b2 22 [2] a9 24 [2] b5 23 [2] a9 0c }

  condition:
    any of them
}