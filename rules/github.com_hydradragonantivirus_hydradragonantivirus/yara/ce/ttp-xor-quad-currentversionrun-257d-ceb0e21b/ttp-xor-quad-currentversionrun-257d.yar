rule TTP_XOR_QUAD_CurrentVersionRun_257d {
  strings:
    $key_257d = { 76 12 [2] 52 1c [2] 79 30 [2] 57 12 [2] 43 09 [2] 4c 13 [2] 52 0e [2] 50 0f [2] 4b 09 [2] 57 0e [2] 4b 21 }

  condition:
    any of them
}