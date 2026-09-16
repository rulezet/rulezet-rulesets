rule TTP_XOR_QUAD_CurrentVersionRun_4cfa {
  strings:
    $key_4cfa = { 1f 95 [2] 3b 9b [2] 10 b7 [2] 3e 95 [2] 2a 8e [2] 25 94 [2] 3b 89 [2] 39 88 [2] 22 8e [2] 3e 89 [2] 22 a6 }

  condition:
    any of them
}