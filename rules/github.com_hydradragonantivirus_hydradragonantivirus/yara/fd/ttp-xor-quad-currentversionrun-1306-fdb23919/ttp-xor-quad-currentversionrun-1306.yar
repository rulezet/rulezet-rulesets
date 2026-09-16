rule TTP_XOR_QUAD_CurrentVersionRun_1306 {
  strings:
    $key_1306 = { 40 69 [2] 64 67 [2] 4f 4b [2] 61 69 [2] 75 72 [2] 7a 68 [2] 64 75 [2] 66 74 [2] 7d 72 [2] 61 75 [2] 7d 5a }

  condition:
    any of them
}