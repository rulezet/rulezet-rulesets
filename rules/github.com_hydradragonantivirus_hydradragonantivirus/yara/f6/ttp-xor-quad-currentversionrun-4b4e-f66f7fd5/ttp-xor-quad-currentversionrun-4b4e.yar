rule TTP_XOR_QUAD_CurrentVersionRun_4b4e {
  strings:
    $key_4b4e = { 18 21 [2] 3c 2f [2] 17 03 [2] 39 21 [2] 2d 3a [2] 22 20 [2] 3c 3d [2] 3e 3c [2] 25 3a [2] 39 3d [2] 25 12 }

  condition:
    any of them
}