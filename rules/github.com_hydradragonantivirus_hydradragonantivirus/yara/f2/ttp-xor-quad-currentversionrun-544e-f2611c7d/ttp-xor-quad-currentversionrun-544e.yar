rule TTP_XOR_QUAD_CurrentVersionRun_544e {
  strings:
    $key_544e = { 07 21 [2] 23 2f [2] 08 03 [2] 26 21 [2] 32 3a [2] 3d 20 [2] 23 3d [2] 21 3c [2] 3a 3a [2] 26 3d [2] 3a 12 }

  condition:
    any of them
}