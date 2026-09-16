rule TTP_XOR_QUAD_CurrentVersionRun_384e {
  strings:
    $key_384e = { 6b 21 [2] 4f 2f [2] 64 03 [2] 4a 21 [2] 5e 3a [2] 51 20 [2] 4f 3d [2] 4d 3c [2] 56 3a [2] 4a 3d [2] 56 12 }

  condition:
    any of them
}