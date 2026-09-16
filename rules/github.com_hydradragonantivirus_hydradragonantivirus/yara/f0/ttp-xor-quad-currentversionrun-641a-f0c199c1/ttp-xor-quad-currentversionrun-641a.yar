rule TTP_XOR_QUAD_CurrentVersionRun_641a {
  strings:
    $key_641a = { 37 75 [2] 13 7b [2] 38 57 [2] 16 75 [2] 02 6e [2] 0d 74 [2] 13 69 [2] 11 68 [2] 0a 6e [2] 16 69 [2] 0a 46 }

  condition:
    any of them
}