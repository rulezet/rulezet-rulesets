rule TTP_XOR_QUAD_CurrentVersionRun_6a5e {
  strings:
    $key_6a5e = { 39 31 [2] 1d 3f [2] 36 13 [2] 18 31 [2] 0c 2a [2] 03 30 [2] 1d 2d [2] 1f 2c [2] 04 2a [2] 18 2d [2] 04 02 }

  condition:
    any of them
}