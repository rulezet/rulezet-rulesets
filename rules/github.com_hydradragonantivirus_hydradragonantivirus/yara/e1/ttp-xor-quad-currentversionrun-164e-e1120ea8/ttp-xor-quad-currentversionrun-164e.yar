rule TTP_XOR_QUAD_CurrentVersionRun_164e {
  strings:
    $key_164e = { 45 21 [2] 61 2f [2] 4a 03 [2] 64 21 [2] 70 3a [2] 7f 20 [2] 61 3d [2] 63 3c [2] 78 3a [2] 64 3d [2] 78 12 }

  condition:
    any of them
}