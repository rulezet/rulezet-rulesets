rule TTP_XOR_QUAD_CurrentVersionRun_1b5f {
  strings:
    $key_1b5f = { 48 30 [2] 6c 3e [2] 47 12 [2] 69 30 [2] 7d 2b [2] 72 31 [2] 6c 2c [2] 6e 2d [2] 75 2b [2] 69 2c [2] 75 03 }

  condition:
    any of them
}