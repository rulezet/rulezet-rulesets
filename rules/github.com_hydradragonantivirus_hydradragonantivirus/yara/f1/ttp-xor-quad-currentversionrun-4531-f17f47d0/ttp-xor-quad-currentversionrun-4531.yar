rule TTP_XOR_QUAD_CurrentVersionRun_4531 {
  strings:
    $key_4531 = { 16 5e [2] 32 50 [2] 19 7c [2] 37 5e [2] 23 45 [2] 2c 5f [2] 32 42 [2] 30 43 [2] 2b 45 [2] 37 42 [2] 2b 6d }

  condition:
    any of them
}