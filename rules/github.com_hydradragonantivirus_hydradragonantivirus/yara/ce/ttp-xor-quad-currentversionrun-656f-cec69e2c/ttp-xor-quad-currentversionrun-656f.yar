rule TTP_XOR_QUAD_CurrentVersionRun_656f {
  strings:
    $key_656f = { 36 00 [2] 12 0e [2] 39 22 [2] 17 00 [2] 03 1b [2] 0c 01 [2] 12 1c [2] 10 1d [2] 0b 1b [2] 17 1c [2] 0b 33 }

  condition:
    any of them
}