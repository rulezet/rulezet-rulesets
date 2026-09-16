rule TTP_XOR_QUAD_CurrentVersionRun_397d {
  strings:
    $key_397d = { 6a 12 [2] 4e 1c [2] 65 30 [2] 4b 12 [2] 5f 09 [2] 50 13 [2] 4e 0e [2] 4c 0f [2] 57 09 [2] 4b 0e [2] 57 21 }

  condition:
    any of them
}