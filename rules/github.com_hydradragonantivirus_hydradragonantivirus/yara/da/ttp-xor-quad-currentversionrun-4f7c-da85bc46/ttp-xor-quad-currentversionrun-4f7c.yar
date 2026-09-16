rule TTP_XOR_QUAD_CurrentVersionRun_4f7c {
  strings:
    $key_4f7c = { 1c 13 [2] 38 1d [2] 13 31 [2] 3d 13 [2] 29 08 [2] 26 12 [2] 38 0f [2] 3a 0e [2] 21 08 [2] 3d 0f [2] 21 20 }

  condition:
    any of them
}