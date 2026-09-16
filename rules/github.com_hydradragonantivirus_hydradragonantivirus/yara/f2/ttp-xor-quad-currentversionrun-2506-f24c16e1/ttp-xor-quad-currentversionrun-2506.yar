rule TTP_XOR_QUAD_CurrentVersionRun_2506 {
  strings:
    $key_2506 = { 76 69 [2] 52 67 [2] 79 4b [2] 57 69 [2] 43 72 [2] 4c 68 [2] 52 75 [2] 50 74 [2] 4b 72 [2] 57 75 [2] 4b 5a }

  condition:
    any of them
}