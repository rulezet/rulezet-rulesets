rule TTP_XOR_QUAD_CurrentVersionRun_6913 {
  strings:
    $key_6913 = { 3a 7c [2] 1e 72 [2] 35 5e [2] 1b 7c [2] 0f 67 [2] 00 7d [2] 1e 60 [2] 1c 61 [2] 07 67 [2] 1b 60 [2] 07 4f }

  condition:
    any of them
}