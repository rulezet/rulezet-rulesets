rule TTP_XOR_QUAD_CurrentVersionRun_4606 {
  strings:
    $key_4606 = { 15 69 [2] 31 67 [2] 1a 4b [2] 34 69 [2] 20 72 [2] 2f 68 [2] 31 75 [2] 33 74 [2] 28 72 [2] 34 75 [2] 28 5a }

  condition:
    any of them
}