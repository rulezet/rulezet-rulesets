rule TTP_XOR_QUAD_CurrentVersionRun_533d {
  strings:
    $key_533d = { 00 52 [2] 24 5c [2] 0f 70 [2] 21 52 [2] 35 49 [2] 3a 53 [2] 24 4e [2] 26 4f [2] 3d 49 [2] 21 4e [2] 3d 61 }

  condition:
    any of them
}