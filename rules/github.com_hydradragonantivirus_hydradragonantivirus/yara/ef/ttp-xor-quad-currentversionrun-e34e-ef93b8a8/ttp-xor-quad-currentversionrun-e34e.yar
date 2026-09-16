rule TTP_XOR_QUAD_CurrentVersionRun_e34e {
  strings:
    $key_e34e = { b0 21 [2] 94 2f [2] bf 03 [2] 91 21 [2] 85 3a [2] 8a 20 [2] 94 3d [2] 96 3c [2] 8d 3a [2] 91 3d [2] 8d 12 }

  condition:
    any of them
}