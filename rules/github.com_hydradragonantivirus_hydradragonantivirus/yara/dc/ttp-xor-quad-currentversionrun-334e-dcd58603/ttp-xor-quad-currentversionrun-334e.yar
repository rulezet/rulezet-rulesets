rule TTP_XOR_QUAD_CurrentVersionRun_334e {
  strings:
    $key_334e = { 60 21 [2] 44 2f [2] 6f 03 [2] 41 21 [2] 55 3a [2] 5a 20 [2] 44 3d [2] 46 3c [2] 5d 3a [2] 41 3d [2] 5d 12 }

  condition:
    any of them
}