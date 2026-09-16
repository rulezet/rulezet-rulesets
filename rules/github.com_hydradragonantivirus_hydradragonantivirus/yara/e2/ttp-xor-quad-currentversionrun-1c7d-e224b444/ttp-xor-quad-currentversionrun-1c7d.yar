rule TTP_XOR_QUAD_CurrentVersionRun_1c7d {
  strings:
    $key_1c7d = { 4f 12 [2] 6b 1c [2] 40 30 [2] 6e 12 [2] 7a 09 [2] 75 13 [2] 6b 0e [2] 69 0f [2] 72 09 [2] 6e 0e [2] 72 21 }

  condition:
    any of them
}