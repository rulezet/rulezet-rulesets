rule TTP_XOR_QUAD_CurrentVersionRun_0c5a {
  strings:
    $key_0c5a = { 5f 35 [2] 7b 3b [2] 50 17 [2] 7e 35 [2] 6a 2e [2] 65 34 [2] 7b 29 [2] 79 28 [2] 62 2e [2] 7e 29 [2] 62 06 }

  condition:
    any of them
}