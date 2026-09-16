rule TTP_XOR_QUAD_CurrentVersionRun_5ced {
  strings:
    $key_5ced = { 0f 82 [2] 2b 8c [2] 00 a0 [2] 2e 82 [2] 3a 99 [2] 35 83 [2] 2b 9e [2] 29 9f [2] 32 99 [2] 2e 9e [2] 32 b1 }

  condition:
    any of them
}