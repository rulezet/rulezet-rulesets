rule TTP_XOR_QUAD_CurrentVersionRun_6a5f {
  strings:
    $key_6a5f = { 39 30 [2] 1d 3e [2] 36 12 [2] 18 30 [2] 0c 2b [2] 03 31 [2] 1d 2c [2] 1f 2d [2] 04 2b [2] 18 2c [2] 04 03 }

  condition:
    any of them
}