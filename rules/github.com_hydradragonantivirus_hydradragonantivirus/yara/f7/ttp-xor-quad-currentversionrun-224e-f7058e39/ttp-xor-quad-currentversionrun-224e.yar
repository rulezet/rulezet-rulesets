rule TTP_XOR_QUAD_CurrentVersionRun_224e {
  strings:
    $key_224e = { 71 21 [2] 55 2f [2] 7e 03 [2] 50 21 [2] 44 3a [2] 4b 20 [2] 55 3d [2] 57 3c [2] 4c 3a [2] 50 3d [2] 4c 12 }

  condition:
    any of them
}