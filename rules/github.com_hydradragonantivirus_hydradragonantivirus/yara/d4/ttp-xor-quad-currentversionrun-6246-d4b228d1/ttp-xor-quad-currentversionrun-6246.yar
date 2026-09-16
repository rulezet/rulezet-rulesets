rule TTP_XOR_QUAD_CurrentVersionRun_6246 {
  strings:
    $key_6246 = { 31 29 [2] 15 27 [2] 3e 0b [2] 10 29 [2] 04 32 [2] 0b 28 [2] 15 35 [2] 17 34 [2] 0c 32 [2] 10 35 [2] 0c 1a }

  condition:
    any of them
}