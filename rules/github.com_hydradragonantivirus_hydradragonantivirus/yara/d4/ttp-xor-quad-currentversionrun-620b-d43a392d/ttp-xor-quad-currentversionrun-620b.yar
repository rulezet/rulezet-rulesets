rule TTP_XOR_QUAD_CurrentVersionRun_620b {
  strings:
    $key_620b = { 31 64 [2] 15 6a [2] 3e 46 [2] 10 64 [2] 04 7f [2] 0b 65 [2] 15 78 [2] 17 79 [2] 0c 7f [2] 10 78 [2] 0c 57 }

  condition:
    any of them
}