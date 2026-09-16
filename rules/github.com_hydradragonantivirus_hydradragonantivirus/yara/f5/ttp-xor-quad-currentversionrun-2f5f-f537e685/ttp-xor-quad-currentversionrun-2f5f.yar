rule TTP_XOR_QUAD_CurrentVersionRun_2f5f {
  strings:
    $key_2f5f = { 7c 30 [2] 58 3e [2] 73 12 [2] 5d 30 [2] 49 2b [2] 46 31 [2] 58 2c [2] 5a 2d [2] 41 2b [2] 5d 2c [2] 41 03 }

  condition:
    any of them
}