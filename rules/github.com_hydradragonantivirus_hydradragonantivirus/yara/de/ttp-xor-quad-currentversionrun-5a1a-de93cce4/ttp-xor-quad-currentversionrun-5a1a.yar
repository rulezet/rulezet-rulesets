rule TTP_XOR_QUAD_CurrentVersionRun_5a1a {
  strings:
    $key_5a1a = { 09 75 [2] 2d 7b [2] 06 57 [2] 28 75 [2] 3c 6e [2] 33 74 [2] 2d 69 [2] 2f 68 [2] 34 6e [2] 28 69 [2] 34 46 }

  condition:
    any of them
}