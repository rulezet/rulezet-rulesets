rule TTP_XOR_QUAD_CurrentVersionRun_6506 {
  strings:
    $key_6506 = { 36 69 [2] 12 67 [2] 39 4b [2] 17 69 [2] 03 72 [2] 0c 68 [2] 12 75 [2] 10 74 [2] 0b 72 [2] 17 75 [2] 0b 5a }

  condition:
    any of them
}