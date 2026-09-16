rule TTP_XOR_QUAD_CurrentVersionRun_5d16 {
  strings:
    $key_5d16 = { 0e 79 [2] 2a 77 [2] 01 5b [2] 2f 79 [2] 3b 62 [2] 34 78 [2] 2a 65 [2] 28 64 [2] 33 62 [2] 2f 65 [2] 33 4a }

  condition:
    any of them
}