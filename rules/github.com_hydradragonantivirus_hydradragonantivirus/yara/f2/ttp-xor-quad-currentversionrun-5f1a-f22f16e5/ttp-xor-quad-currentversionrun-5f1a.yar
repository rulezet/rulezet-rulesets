rule TTP_XOR_QUAD_CurrentVersionRun_5f1a {
  strings:
    $key_5f1a = { 0c 75 [2] 28 7b [2] 03 57 [2] 2d 75 [2] 39 6e [2] 36 74 [2] 28 69 [2] 2a 68 [2] 31 6e [2] 2d 69 [2] 31 46 }

  condition:
    any of them
}