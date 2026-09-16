rule TTP_XOR_QUAD_CurrentVersionRun_6306 {
  strings:
    $key_6306 = { 30 69 [2] 14 67 [2] 3f 4b [2] 11 69 [2] 05 72 [2] 0a 68 [2] 14 75 [2] 16 74 [2] 0d 72 [2] 11 75 [2] 0d 5a }

  condition:
    any of them
}