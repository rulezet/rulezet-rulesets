rule TTP_XOR_QUAD_CurrentVersionRun_c733 {
  strings:
    $key_c733 = { 94 5c [2] b0 52 [2] 9b 7e [2] b5 5c [2] a1 47 [2] ae 5d [2] b0 40 [2] b2 41 [2] a9 47 [2] b5 40 [2] a9 6f }

  condition:
    any of them
}