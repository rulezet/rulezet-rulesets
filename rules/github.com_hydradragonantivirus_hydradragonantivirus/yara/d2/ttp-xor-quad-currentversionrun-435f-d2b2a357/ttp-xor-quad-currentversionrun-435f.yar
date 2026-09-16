rule TTP_XOR_QUAD_CurrentVersionRun_435f {
  strings:
    $key_435f = { 10 30 [2] 34 3e [2] 1f 12 [2] 31 30 [2] 25 2b [2] 2a 31 [2] 34 2c [2] 36 2d [2] 2d 2b [2] 31 2c [2] 2d 03 }

  condition:
    any of them
}