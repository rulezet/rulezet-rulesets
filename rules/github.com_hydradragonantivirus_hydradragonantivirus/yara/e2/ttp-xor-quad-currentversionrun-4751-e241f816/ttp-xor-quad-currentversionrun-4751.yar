rule TTP_XOR_QUAD_CurrentVersionRun_4751 {
  strings:
    $key_4751 = { 14 3e [2] 30 30 [2] 1b 1c [2] 35 3e [2] 21 25 [2] 2e 3f [2] 30 22 [2] 32 23 [2] 29 25 [2] 35 22 [2] 29 0d }

  condition:
    any of them
}