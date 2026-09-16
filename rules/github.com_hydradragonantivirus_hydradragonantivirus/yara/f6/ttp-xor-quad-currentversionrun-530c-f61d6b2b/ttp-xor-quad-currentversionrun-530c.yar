rule TTP_XOR_QUAD_CurrentVersionRun_530c {
  strings:
    $key_530c = { 00 63 [2] 24 6d [2] 0f 41 [2] 21 63 [2] 35 78 [2] 3a 62 [2] 24 7f [2] 26 7e [2] 3d 78 [2] 21 7f [2] 3d 50 }

  condition:
    any of them
}