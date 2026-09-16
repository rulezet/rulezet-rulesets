rule TTP_XOR_QUAD_CurrentVersionRun_4f4c {
  strings:
    $key_4f4c = { 1c 23 [2] 38 2d [2] 13 01 [2] 3d 23 [2] 29 38 [2] 26 22 [2] 38 3f [2] 3a 3e [2] 21 38 [2] 3d 3f [2] 21 10 }

  condition:
    any of them
}