rule TTP_XOR_QUAD_CurrentVersionRun_534e {
  strings:
    $key_534e = { 00 21 [2] 24 2f [2] 0f 03 [2] 21 21 [2] 35 3a [2] 3a 20 [2] 24 3d [2] 26 3c [2] 3d 3a [2] 21 3d [2] 3d 12 }

  condition:
    any of them
}