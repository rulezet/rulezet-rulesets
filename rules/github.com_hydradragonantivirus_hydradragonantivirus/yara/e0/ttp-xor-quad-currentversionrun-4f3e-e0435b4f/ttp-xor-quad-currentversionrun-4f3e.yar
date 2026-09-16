rule TTP_XOR_QUAD_CurrentVersionRun_4f3e {
  strings:
    $key_4f3e = { 1c 51 [2] 38 5f [2] 13 73 [2] 3d 51 [2] 29 4a [2] 26 50 [2] 38 4d [2] 3a 4c [2] 21 4a [2] 3d 4d [2] 21 62 }

  condition:
    any of them
}