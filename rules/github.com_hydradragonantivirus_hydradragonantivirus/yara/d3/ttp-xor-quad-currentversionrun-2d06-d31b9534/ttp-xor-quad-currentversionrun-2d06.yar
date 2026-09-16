rule TTP_XOR_QUAD_CurrentVersionRun_2d06 {
  strings:
    $key_2d06 = { 7e 69 [2] 5a 67 [2] 71 4b [2] 5f 69 [2] 4b 72 [2] 44 68 [2] 5a 75 [2] 58 74 [2] 43 72 [2] 5f 75 [2] 43 5a }

  condition:
    any of them
}