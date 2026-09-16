rule TTP_XOR_QUAD_CurrentVersionRun_7606 {
  strings:
    $key_7606 = { 25 69 [2] 01 67 [2] 2a 4b [2] 04 69 [2] 10 72 [2] 1f 68 [2] 01 75 [2] 03 74 [2] 18 72 [2] 04 75 [2] 18 5a }

  condition:
    any of them
}