rule TTP_XOR_QUAD_CurrentVersionRun_7f5f {
  strings:
    $key_7f5f = { 2c 30 [2] 08 3e [2] 23 12 [2] 0d 30 [2] 19 2b [2] 16 31 [2] 08 2c [2] 0a 2d [2] 11 2b [2] 0d 2c [2] 11 03 }

  condition:
    any of them
}