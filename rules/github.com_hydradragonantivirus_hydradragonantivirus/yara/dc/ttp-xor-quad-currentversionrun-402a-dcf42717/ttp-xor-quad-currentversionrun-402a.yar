rule TTP_XOR_QUAD_CurrentVersionRun_402a {
  strings:
    $key_402a = { 13 45 [2] 37 4b [2] 1c 67 [2] 32 45 [2] 26 5e [2] 29 44 [2] 37 59 [2] 35 58 [2] 2e 5e [2] 32 59 [2] 2e 76 }

  condition:
    any of them
}