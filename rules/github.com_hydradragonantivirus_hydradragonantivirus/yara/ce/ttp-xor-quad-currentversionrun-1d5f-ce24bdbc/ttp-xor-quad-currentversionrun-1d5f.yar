rule TTP_XOR_QUAD_CurrentVersionRun_1d5f {
  strings:
    $key_1d5f = { 4e 30 [2] 6a 3e [2] 41 12 [2] 6f 30 [2] 7b 2b [2] 74 31 [2] 6a 2c [2] 68 2d [2] 73 2b [2] 6f 2c [2] 73 03 }

  condition:
    any of them
}