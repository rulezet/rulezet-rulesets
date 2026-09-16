rule TTP_XOR_QUAD_CurrentVersionRun_255a {
  strings:
    $key_255a = { 76 35 [2] 52 3b [2] 79 17 [2] 57 35 [2] 43 2e [2] 4c 34 [2] 52 29 [2] 50 28 [2] 4b 2e [2] 57 29 [2] 4b 06 }

  condition:
    any of them
}