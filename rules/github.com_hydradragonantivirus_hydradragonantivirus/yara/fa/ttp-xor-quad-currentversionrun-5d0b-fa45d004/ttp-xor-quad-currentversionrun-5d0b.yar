rule TTP_XOR_QUAD_CurrentVersionRun_5d0b {
  strings:
    $key_5d0b = { 0e 64 [2] 2a 6a [2] 01 46 [2] 2f 64 [2] 3b 7f [2] 34 65 [2] 2a 78 [2] 28 79 [2] 33 7f [2] 2f 78 [2] 33 57 }

  condition:
    any of them
}