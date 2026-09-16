rule TTP_XOR_QUAD_CurrentVersionRun_227d {
  strings:
    $key_227d = { 71 12 [2] 55 1c [2] 7e 30 [2] 50 12 [2] 44 09 [2] 4b 13 [2] 55 0e [2] 57 0f [2] 4c 09 [2] 50 0e [2] 4c 21 }

  condition:
    any of them
}