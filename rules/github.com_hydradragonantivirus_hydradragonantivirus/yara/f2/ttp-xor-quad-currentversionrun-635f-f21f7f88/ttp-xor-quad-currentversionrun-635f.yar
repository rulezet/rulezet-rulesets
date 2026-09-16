rule TTP_XOR_QUAD_CurrentVersionRun_635f {
  strings:
    $key_635f = { 30 30 [2] 14 3e [2] 3f 12 [2] 11 30 [2] 05 2b [2] 0a 31 [2] 14 2c [2] 16 2d [2] 0d 2b [2] 11 2c [2] 0d 03 }

  condition:
    any of them
}