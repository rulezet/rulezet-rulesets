rule TTP_XOR_QUAD_CurrentVersionRun_761a {
  strings:
    $key_761a = { 25 75 [2] 01 7b [2] 2a 57 [2] 04 75 [2] 10 6e [2] 1f 74 [2] 01 69 [2] 03 68 [2] 18 6e [2] 04 69 [2] 18 46 }

  condition:
    any of them
}