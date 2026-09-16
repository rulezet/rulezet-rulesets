rule TTP_XOR_QUAD_CurrentVersionRun_144e {
  strings:
    $key_144e = { 47 21 [2] 63 2f [2] 48 03 [2] 66 21 [2] 72 3a [2] 7d 20 [2] 63 3d [2] 61 3c [2] 7a 3a [2] 66 3d [2] 7a 12 }

  condition:
    any of them
}