rule TTP_XOR_QUAD_CurrentVersionRun_5f5f {
  strings:
    $key_5f5f = { 0c 30 [2] 28 3e [2] 03 12 [2] 2d 30 [2] 39 2b [2] 36 31 [2] 28 2c [2] 2a 2d [2] 31 2b [2] 2d 2c [2] 31 03 }

  condition:
    any of them
}