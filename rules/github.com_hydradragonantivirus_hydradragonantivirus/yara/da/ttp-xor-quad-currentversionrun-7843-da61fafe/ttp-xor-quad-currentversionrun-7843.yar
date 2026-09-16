rule TTP_XOR_QUAD_CurrentVersionRun_7843 {
  strings:
    $key_7843 = { 2b 2c [2] 0f 22 [2] 24 0e [2] 0a 2c [2] 1e 37 [2] 11 2d [2] 0f 30 [2] 0d 31 [2] 16 37 [2] 0a 30 [2] 16 1f }

  condition:
    any of them
}