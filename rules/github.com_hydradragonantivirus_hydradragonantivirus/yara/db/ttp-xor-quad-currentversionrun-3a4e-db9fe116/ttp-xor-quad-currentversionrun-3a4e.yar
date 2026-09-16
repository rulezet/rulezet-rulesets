rule TTP_XOR_QUAD_CurrentVersionRun_3a4e {
  strings:
    $key_3a4e = { 69 21 [2] 4d 2f [2] 66 03 [2] 48 21 [2] 5c 3a [2] 53 20 [2] 4d 3d [2] 4f 3c [2] 54 3a [2] 48 3d [2] 54 12 }

  condition:
    any of them
}