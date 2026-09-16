rule TTP_XOR_QUAD_CurrentVersionRun_c703 {
  strings:
    $key_c703 = { 94 6c [2] b0 62 [2] 9b 4e [2] b5 6c [2] a1 77 [2] ae 6d [2] b0 70 [2] b2 71 [2] a9 77 [2] b5 70 [2] a9 5f }

  condition:
    any of them
}