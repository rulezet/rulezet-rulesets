rule TTP_XOR_QUAD_CurrentVersionRun_6d5f {
  strings:
    $key_6d5f = { 3e 30 [2] 1a 3e [2] 31 12 [2] 1f 30 [2] 0b 2b [2] 04 31 [2] 1a 2c [2] 18 2d [2] 03 2b [2] 1f 2c [2] 03 03 }

  condition:
    any of them
}