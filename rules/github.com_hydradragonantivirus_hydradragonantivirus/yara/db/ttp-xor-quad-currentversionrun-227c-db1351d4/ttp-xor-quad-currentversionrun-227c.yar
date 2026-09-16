rule TTP_XOR_QUAD_CurrentVersionRun_227c {
  strings:
    $key_227c = { 71 13 [2] 55 1d [2] 7e 31 [2] 50 13 [2] 44 08 [2] 4b 12 [2] 55 0f [2] 57 0e [2] 4c 08 [2] 50 0f [2] 4c 20 }

  condition:
    any of them
}