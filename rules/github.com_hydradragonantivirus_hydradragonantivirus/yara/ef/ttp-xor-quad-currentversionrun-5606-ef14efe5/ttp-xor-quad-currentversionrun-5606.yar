rule TTP_XOR_QUAD_CurrentVersionRun_5606 {
  strings:
    $key_5606 = { 05 69 [2] 21 67 [2] 0a 4b [2] 24 69 [2] 30 72 [2] 3f 68 [2] 21 75 [2] 23 74 [2] 38 72 [2] 24 75 [2] 38 5a }

  condition:
    any of them
}