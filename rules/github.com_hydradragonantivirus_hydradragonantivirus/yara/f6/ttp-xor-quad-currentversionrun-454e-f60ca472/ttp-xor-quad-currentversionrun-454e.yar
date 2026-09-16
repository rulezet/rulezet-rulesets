rule TTP_XOR_QUAD_CurrentVersionRun_454e {
  strings:
    $key_454e = { 16 21 [2] 32 2f [2] 19 03 [2] 37 21 [2] 23 3a [2] 2c 20 [2] 32 3d [2] 30 3c [2] 2b 3a [2] 37 3d [2] 2b 12 }

  condition:
    any of them
}