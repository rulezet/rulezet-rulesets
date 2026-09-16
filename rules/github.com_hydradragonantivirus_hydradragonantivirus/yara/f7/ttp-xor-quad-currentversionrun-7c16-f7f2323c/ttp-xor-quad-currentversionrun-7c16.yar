rule TTP_XOR_QUAD_CurrentVersionRun_7c16 {
  strings:
    $key_7c16 = { 2f 79 [2] 0b 77 [2] 20 5b [2] 0e 79 [2] 1a 62 [2] 15 78 [2] 0b 65 [2] 09 64 [2] 12 62 [2] 0e 65 [2] 12 4a }

  condition:
    any of them
}