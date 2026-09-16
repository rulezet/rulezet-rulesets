rule TTP_XOR_QUAD_CurrentVersionRun_645f {
  strings:
    $key_645f = { 37 30 [2] 13 3e [2] 38 12 [2] 16 30 [2] 02 2b [2] 0d 31 [2] 13 2c [2] 11 2d [2] 0a 2b [2] 16 2c [2] 0a 03 }

  condition:
    any of them
}