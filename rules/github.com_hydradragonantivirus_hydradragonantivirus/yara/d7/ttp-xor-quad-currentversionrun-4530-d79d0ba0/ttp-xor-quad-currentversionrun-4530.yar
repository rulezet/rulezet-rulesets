rule TTP_XOR_QUAD_CurrentVersionRun_4530 {
  strings:
    $key_4530 = { 16 5f [2] 32 51 [2] 19 7d [2] 37 5f [2] 23 44 [2] 2c 5e [2] 32 43 [2] 30 42 [2] 2b 44 [2] 37 43 [2] 2b 6c }

  condition:
    any of them
}