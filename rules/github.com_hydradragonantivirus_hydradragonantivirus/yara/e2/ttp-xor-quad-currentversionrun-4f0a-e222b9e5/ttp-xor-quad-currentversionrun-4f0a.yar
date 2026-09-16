rule TTP_XOR_QUAD_CurrentVersionRun_4f0a {
  strings:
    $key_4f0a = { 1c 65 [2] 38 6b [2] 13 47 [2] 3d 65 [2] 29 7e [2] 26 64 [2] 38 79 [2] 3a 78 [2] 21 7e [2] 3d 79 [2] 21 56 }

  condition:
    any of them
}