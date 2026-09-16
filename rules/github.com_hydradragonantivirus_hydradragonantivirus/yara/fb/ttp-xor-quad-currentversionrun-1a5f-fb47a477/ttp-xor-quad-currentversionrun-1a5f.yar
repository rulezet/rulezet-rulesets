rule TTP_XOR_QUAD_CurrentVersionRun_1a5f {
  strings:
    $key_1a5f = { 49 30 [2] 6d 3e [2] 46 12 [2] 68 30 [2] 7c 2b [2] 73 31 [2] 6d 2c [2] 6f 2d [2] 74 2b [2] 68 2c [2] 74 03 }

  condition:
    any of them
}