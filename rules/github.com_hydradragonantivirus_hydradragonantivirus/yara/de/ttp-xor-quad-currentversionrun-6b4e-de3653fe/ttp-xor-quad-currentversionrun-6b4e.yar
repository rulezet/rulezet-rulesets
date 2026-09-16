rule TTP_XOR_QUAD_CurrentVersionRun_6b4e {
  strings:
    $key_6b4e = { 38 21 [2] 1c 2f [2] 37 03 [2] 19 21 [2] 0d 3a [2] 02 20 [2] 1c 3d [2] 1e 3c [2] 05 3a [2] 19 3d [2] 05 12 }

  condition:
    any of them
}