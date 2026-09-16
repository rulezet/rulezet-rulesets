rule TTP_XOR_QUAD_CurrentVersionRun_1e4e {
  strings:
    $key_1e4e = { 4d 21 [2] 69 2f [2] 42 03 [2] 6c 21 [2] 78 3a [2] 77 20 [2] 69 3d [2] 6b 3c [2] 70 3a [2] 6c 3d [2] 70 12 }

  condition:
    any of them
}