rule TTP_XOR_QUAD_CurrentVersionRun_367a {
  strings:
    $key_367a = { 65 15 [2] 41 1b [2] 6a 37 [2] 44 15 [2] 50 0e [2] 5f 14 [2] 41 09 [2] 43 08 [2] 58 0e [2] 44 09 [2] 58 26 }

  condition:
    any of them
}