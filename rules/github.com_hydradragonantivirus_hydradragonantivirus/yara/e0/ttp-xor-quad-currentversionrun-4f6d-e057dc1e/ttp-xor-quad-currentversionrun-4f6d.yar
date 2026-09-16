rule TTP_XOR_QUAD_CurrentVersionRun_4f6d {
  strings:
    $key_4f6d = { 1c 02 [2] 38 0c [2] 13 20 [2] 3d 02 [2] 29 19 [2] 26 03 [2] 38 1e [2] 3a 1f [2] 21 19 [2] 3d 1e [2] 21 31 }

  condition:
    any of them
}