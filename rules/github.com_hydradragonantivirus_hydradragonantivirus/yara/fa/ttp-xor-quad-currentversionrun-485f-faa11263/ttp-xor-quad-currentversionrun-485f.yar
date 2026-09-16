rule TTP_XOR_QUAD_CurrentVersionRun_485f {
  strings:
    $key_485f = { 1b 30 [2] 3f 3e [2] 14 12 [2] 3a 30 [2] 2e 2b [2] 21 31 [2] 3f 2c [2] 3d 2d [2] 26 2b [2] 3a 2c [2] 26 03 }

  condition:
    any of them
}