rule TTP_XOR_QUAD_CurrentVersionRun_344e {
  strings:
    $key_344e = { 67 21 [2] 43 2f [2] 68 03 [2] 46 21 [2] 52 3a [2] 5d 20 [2] 43 3d [2] 41 3c [2] 5a 3a [2] 46 3d [2] 5a 12 }

  condition:
    any of them
}