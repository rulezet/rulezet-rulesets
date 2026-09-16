rule TTP_XOR_QUAD_CurrentVersionRun_c731 {
  strings:
    $key_c731 = { 94 5e [2] b0 50 [2] 9b 7c [2] b5 5e [2] a1 45 [2] ae 5f [2] b0 42 [2] b2 43 [2] a9 45 [2] b5 42 [2] a9 6d }

  condition:
    any of them
}