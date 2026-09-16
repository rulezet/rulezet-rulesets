rule TTP_XOR_QUAD_CurrentVersionRun_c716 {
  strings:
    $key_c716 = { 94 79 [2] b0 77 [2] 9b 5b [2] b5 79 [2] a1 62 [2] ae 78 [2] b0 65 [2] b2 64 [2] a9 62 [2] b5 65 [2] a9 4a }

  condition:
    any of them
}