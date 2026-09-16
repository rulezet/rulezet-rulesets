rule TTP_XOR_QUAD_CurrentVersionRun_671a {
  strings:
    $key_671a = { 34 75 [2] 10 7b [2] 3b 57 [2] 15 75 [2] 01 6e [2] 0e 74 [2] 10 69 [2] 12 68 [2] 09 6e [2] 15 69 [2] 09 46 }

  condition:
    any of them
}