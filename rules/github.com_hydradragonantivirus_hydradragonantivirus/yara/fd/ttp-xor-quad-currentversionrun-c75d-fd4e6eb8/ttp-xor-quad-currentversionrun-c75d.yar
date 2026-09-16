rule TTP_XOR_QUAD_CurrentVersionRun_c75d {
  strings:
    $key_c75d = { 94 32 [2] b0 3c [2] 9b 10 [2] b5 32 [2] a1 29 [2] ae 33 [2] b0 2e [2] b2 2f [2] a9 29 [2] b5 2e [2] a9 01 }

  condition:
    any of them
}