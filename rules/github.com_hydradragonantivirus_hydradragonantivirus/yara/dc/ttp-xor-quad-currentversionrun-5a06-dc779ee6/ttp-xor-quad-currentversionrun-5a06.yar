rule TTP_XOR_QUAD_CurrentVersionRun_5a06 {
  strings:
    $key_5a06 = { 09 69 [2] 2d 67 [2] 06 4b [2] 28 69 [2] 3c 72 [2] 33 68 [2] 2d 75 [2] 2f 74 [2] 34 72 [2] 28 75 [2] 34 5a }

  condition:
    any of them
}