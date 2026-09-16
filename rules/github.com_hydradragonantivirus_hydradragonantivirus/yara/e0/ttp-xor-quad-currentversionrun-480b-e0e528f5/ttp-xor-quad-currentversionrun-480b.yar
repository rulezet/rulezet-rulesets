rule TTP_XOR_QUAD_CurrentVersionRun_480b {
  strings:
    $key_480b = { 1b 64 [2] 3f 6a [2] 14 46 [2] 3a 64 [2] 2e 7f [2] 21 65 [2] 3f 78 [2] 3d 79 [2] 26 7f [2] 3a 78 [2] 26 57 }

  condition:
    any of them
}