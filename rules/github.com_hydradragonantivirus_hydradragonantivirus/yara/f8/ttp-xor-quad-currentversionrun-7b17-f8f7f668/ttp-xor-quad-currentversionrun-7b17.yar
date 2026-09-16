rule TTP_XOR_QUAD_CurrentVersionRun_7b17 {
  strings:
    $key_7b17 = { 28 78 [2] 0c 76 [2] 27 5a [2] 09 78 [2] 1d 63 [2] 12 79 [2] 0c 64 [2] 0e 65 [2] 15 63 [2] 09 64 [2] 15 4b }

  condition:
    any of them
}