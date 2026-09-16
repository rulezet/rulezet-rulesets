rule TTP_XOR_QUAD_CurrentVersionRun_251a {
  strings:
    $key_251a = { 76 75 [2] 52 7b [2] 79 57 [2] 57 75 [2] 43 6e [2] 4c 74 [2] 52 69 [2] 50 68 [2] 4b 6e [2] 57 69 [2] 4b 46 }

  condition:
    any of them
}