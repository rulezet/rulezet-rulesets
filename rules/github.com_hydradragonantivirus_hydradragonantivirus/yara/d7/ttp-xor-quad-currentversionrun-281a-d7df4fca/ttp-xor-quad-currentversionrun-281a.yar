rule TTP_XOR_QUAD_CurrentVersionRun_281a {
  strings:
    $key_281a = { 7b 75 [2] 5f 7b [2] 74 57 [2] 5a 75 [2] 4e 6e [2] 41 74 [2] 5f 69 [2] 5d 68 [2] 46 6e [2] 5a 69 [2] 46 46 }

  condition:
    any of them
}