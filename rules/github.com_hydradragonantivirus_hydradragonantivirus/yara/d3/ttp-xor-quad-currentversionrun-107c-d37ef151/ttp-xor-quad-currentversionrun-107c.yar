rule TTP_XOR_QUAD_CurrentVersionRun_107c {
  strings:
    $key_107c = { 43 13 [2] 67 1d [2] 4c 31 [2] 62 13 [2] 76 08 [2] 79 12 [2] 67 0f [2] 65 0e [2] 7e 08 [2] 62 0f [2] 7e 20 }

  condition:
    any of them
}