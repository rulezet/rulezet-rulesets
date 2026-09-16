rule TTP_XOR_QUAD_CurrentVersionRun_185f {
  strings:
    $key_185f = { 4b 30 [2] 6f 3e [2] 44 12 [2] 6a 30 [2] 7e 2b [2] 71 31 [2] 6f 2c [2] 6d 2d [2] 76 2b [2] 6a 2c [2] 76 03 }

  condition:
    any of them
}