rule TTP_XOR_QUAD_CurrentVersionRun_6f5f {
  strings:
    $key_6f5f = { 3c 30 [2] 18 3e [2] 33 12 [2] 1d 30 [2] 09 2b [2] 06 31 [2] 18 2c [2] 1a 2d [2] 01 2b [2] 1d 2c [2] 01 03 }

  condition:
    any of them
}