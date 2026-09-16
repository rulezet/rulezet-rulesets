rule TTP_XOR_QUAD_CurrentVersionRun_7306 {
  strings:
    $key_7306 = { 20 69 [2] 04 67 [2] 2f 4b [2] 01 69 [2] 15 72 [2] 1a 68 [2] 04 75 [2] 06 74 [2] 1d 72 [2] 01 75 [2] 1d 5a }

  condition:
    any of them
}