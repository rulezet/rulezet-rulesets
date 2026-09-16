rule TTP_XOR_QUAD_CurrentVersionRun_4f2a {
  strings:
    $key_4f2a = { 1c 45 [2] 38 4b [2] 13 67 [2] 3d 45 [2] 29 5e [2] 26 44 [2] 38 59 [2] 3a 58 [2] 21 5e [2] 3d 59 [2] 21 76 }

  condition:
    any of them
}