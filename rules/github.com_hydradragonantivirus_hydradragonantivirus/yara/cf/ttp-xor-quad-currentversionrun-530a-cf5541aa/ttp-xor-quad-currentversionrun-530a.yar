rule TTP_XOR_QUAD_CurrentVersionRun_530a {
  strings:
    $key_530a = { 00 65 [2] 24 6b [2] 0f 47 [2] 21 65 [2] 35 7e [2] 3a 64 [2] 24 79 [2] 26 78 [2] 3d 7e [2] 21 79 [2] 3d 56 }

  condition:
    any of them
}