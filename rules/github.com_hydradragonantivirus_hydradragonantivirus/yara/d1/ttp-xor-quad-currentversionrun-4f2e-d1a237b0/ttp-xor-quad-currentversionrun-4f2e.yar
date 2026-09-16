rule TTP_XOR_QUAD_CurrentVersionRun_4f2e {
  strings:
    $key_4f2e = { 1c 41 [2] 38 4f [2] 13 63 [2] 3d 41 [2] 29 5a [2] 26 40 [2] 38 5d [2] 3a 5c [2] 21 5a [2] 3d 5d [2] 21 72 }

  condition:
    any of them
}