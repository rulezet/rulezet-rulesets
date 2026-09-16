rule TTP_XOR_QUAD_CurrentVersionRun_4f7e {
  strings:
    $key_4f7e = { 1c 11 [2] 38 1f [2] 13 33 [2] 3d 11 [2] 29 0a [2] 26 10 [2] 38 0d [2] 3a 0c [2] 21 0a [2] 3d 0d [2] 21 22 }

  condition:
    any of them
}