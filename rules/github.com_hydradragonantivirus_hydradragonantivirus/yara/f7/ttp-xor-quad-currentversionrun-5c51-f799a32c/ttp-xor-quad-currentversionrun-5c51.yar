rule TTP_XOR_QUAD_CurrentVersionRun_5c51 {
  strings:
    $key_5c51 = { 0f 3e [2] 2b 30 [2] 00 1c [2] 2e 3e [2] 3a 25 [2] 35 3f [2] 2b 22 [2] 29 23 [2] 32 25 [2] 2e 22 [2] 32 0d }

  condition:
    any of them
}