rule TTP_XOR_QUAD_CurrentVersionRun_657d {
  strings:
    $key_657d = { 36 12 [2] 12 1c [2] 39 30 [2] 17 12 [2] 03 09 [2] 0c 13 [2] 12 0e [2] 10 0f [2] 0b 09 [2] 17 0e [2] 0b 21 }

  condition:
    any of them
}