rule TTP_XOR_QUAD_CurrentVersionRun_4031 {
  strings:
    $key_4031 = { 13 5e [2] 37 50 [2] 1c 7c [2] 32 5e [2] 26 45 [2] 29 5f [2] 37 42 [2] 35 43 [2] 2e 45 [2] 32 42 [2] 2e 6d }

  condition:
    any of them
}