rule TTP_XOR_QUAD_CurrentVersionRun_4006 {
  strings:
    $key_4006 = { 13 69 [2] 37 67 [2] 1c 4b [2] 32 69 [2] 26 72 [2] 29 68 [2] 37 75 [2] 35 74 [2] 2e 72 [2] 32 75 [2] 2e 5a }

  condition:
    any of them
}