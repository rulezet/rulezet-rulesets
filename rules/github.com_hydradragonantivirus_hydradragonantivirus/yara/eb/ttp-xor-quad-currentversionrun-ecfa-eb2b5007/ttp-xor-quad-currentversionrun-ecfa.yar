rule TTP_XOR_QUAD_CurrentVersionRun_ecfa {
  strings:
    $key_ecfa = { bf 95 [2] 9b 9b [2] b0 b7 [2] 9e 95 [2] 8a 8e [2] 85 94 [2] 9b 89 [2] 99 88 [2] 82 8e [2] 9e 89 [2] 82 a6 }

  condition:
    any of them
}