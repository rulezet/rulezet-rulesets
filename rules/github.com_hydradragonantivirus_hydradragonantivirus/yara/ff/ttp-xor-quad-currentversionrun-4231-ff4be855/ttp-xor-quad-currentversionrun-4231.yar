rule TTP_XOR_QUAD_CurrentVersionRun_4231 {
  strings:
    $key_4231 = { 11 5e [2] 35 50 [2] 1e 7c [2] 30 5e [2] 24 45 [2] 2b 5f [2] 35 42 [2] 37 43 [2] 2c 45 [2] 30 42 [2] 2c 6d }

  condition:
    any of them
}