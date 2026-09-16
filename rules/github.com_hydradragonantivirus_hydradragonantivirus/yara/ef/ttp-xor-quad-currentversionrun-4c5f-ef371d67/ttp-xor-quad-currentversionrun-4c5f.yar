rule TTP_XOR_QUAD_CurrentVersionRun_4c5f {
  strings:
    $key_4c5f = { 1f 30 [2] 3b 3e [2] 10 12 [2] 3e 30 [2] 2a 2b [2] 25 31 [2] 3b 2c [2] 39 2d [2] 22 2b [2] 3e 2c [2] 22 03 }

  condition:
    any of them
}