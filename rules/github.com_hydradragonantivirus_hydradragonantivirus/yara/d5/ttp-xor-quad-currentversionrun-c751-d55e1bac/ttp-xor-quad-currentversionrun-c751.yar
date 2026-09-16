rule TTP_XOR_QUAD_CurrentVersionRun_c751 {
  strings:
    $key_c751 = { 94 3e [2] b0 30 [2] 9b 1c [2] b5 3e [2] a1 25 [2] ae 3f [2] b0 22 [2] b2 23 [2] a9 25 [2] b5 22 [2] a9 0d }

  condition:
    any of them
}