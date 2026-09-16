rule TTP_XOR_QUAD_CurrentVersionRun_536d {
  strings:
    $key_536d = { 00 02 [2] 24 0c [2] 0f 20 [2] 21 02 [2] 35 19 [2] 3a 03 [2] 24 1e [2] 26 1f [2] 3d 19 [2] 21 1e [2] 3d 31 }

  condition:
    any of them
}