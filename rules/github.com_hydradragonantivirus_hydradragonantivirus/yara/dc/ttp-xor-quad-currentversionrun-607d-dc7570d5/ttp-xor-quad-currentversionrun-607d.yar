rule TTP_XOR_QUAD_CurrentVersionRun_607d {
  strings:
    $key_607d = { 33 12 [2] 17 1c [2] 3c 30 [2] 12 12 [2] 06 09 [2] 09 13 [2] 17 0e [2] 15 0f [2] 0e 09 [2] 12 0e [2] 0e 21 }

  condition:
    any of them
}