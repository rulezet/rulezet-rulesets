rule TTP_XOR_QUAD_CurrentVersionRun_314e {
  strings:
    $key_314e = { 62 21 [2] 46 2f [2] 6d 03 [2] 43 21 [2] 57 3a [2] 58 20 [2] 46 3d [2] 44 3c [2] 5f 3a [2] 43 3d [2] 5f 12 }

  condition:
    any of them
}