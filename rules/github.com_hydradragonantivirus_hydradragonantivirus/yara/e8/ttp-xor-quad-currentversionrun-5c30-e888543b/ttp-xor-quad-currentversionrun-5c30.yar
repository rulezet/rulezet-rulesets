rule TTP_XOR_QUAD_CurrentVersionRun_5c30 {
  strings:
    $key_5c30 = { 0f 5f [2] 2b 51 [2] 00 7d [2] 2e 5f [2] 3a 44 [2] 35 5e [2] 2b 43 [2] 29 42 [2] 32 44 [2] 2e 43 [2] 32 6c }

  condition:
    any of them
}