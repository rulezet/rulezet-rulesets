rule TTP_XOR_QUAD_CurrentVersionRun_7c17 {
  strings:
    $key_7c17 = { 2f 78 [2] 0b 76 [2] 20 5a [2] 0e 78 [2] 1a 63 [2] 15 79 [2] 0b 64 [2] 09 65 [2] 12 63 [2] 0e 64 [2] 12 4b }

  condition:
    any of them
}