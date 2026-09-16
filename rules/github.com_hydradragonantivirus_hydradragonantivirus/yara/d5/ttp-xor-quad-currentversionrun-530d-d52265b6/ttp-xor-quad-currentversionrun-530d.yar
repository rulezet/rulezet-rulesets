rule TTP_XOR_QUAD_CurrentVersionRun_530d {
  strings:
    $key_530d = { 00 62 [2] 24 6c [2] 0f 40 [2] 21 62 [2] 35 79 [2] 3a 63 [2] 24 7e [2] 26 7f [2] 3d 79 [2] 21 7e [2] 3d 51 }

  condition:
    any of them
}