rule TTP_XOR_QUAD_CurrentVersionRun_4563 {
  strings:
    $key_4563 = { 16 0c [2] 32 02 [2] 19 2e [2] 37 0c [2] 23 17 [2] 2c 0d [2] 32 10 [2] 30 11 [2] 2b 17 [2] 37 10 [2] 2b 3f }

  condition:
    any of them
}