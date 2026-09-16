rule TTP_XOR_QUAD_CurrentVersionRun_1506 {
  strings:
    $key_1506 = { 46 69 [2] 62 67 [2] 49 4b [2] 67 69 [2] 73 72 [2] 7c 68 [2] 62 75 [2] 60 74 [2] 7b 72 [2] 67 75 [2] 7b 5a }

  condition:
    any of them
}