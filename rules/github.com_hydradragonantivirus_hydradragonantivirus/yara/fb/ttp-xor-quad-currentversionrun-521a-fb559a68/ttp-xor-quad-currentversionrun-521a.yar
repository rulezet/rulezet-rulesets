rule TTP_XOR_QUAD_CurrentVersionRun_521a {
  strings:
    $key_521a = { 01 75 [2] 25 7b [2] 0e 57 [2] 20 75 [2] 34 6e [2] 3b 74 [2] 25 69 [2] 27 68 [2] 3c 6e [2] 20 69 [2] 3c 46 }

  condition:
    any of them
}