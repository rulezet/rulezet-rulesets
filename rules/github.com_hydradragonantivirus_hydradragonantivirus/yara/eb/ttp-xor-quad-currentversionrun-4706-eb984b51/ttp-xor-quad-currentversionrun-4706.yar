rule TTP_XOR_QUAD_CurrentVersionRun_4706 {
  strings:
    $key_4706 = { 14 69 [2] 30 67 [2] 1b 4b [2] 35 69 [2] 21 72 [2] 2e 68 [2] 30 75 [2] 32 74 [2] 29 72 [2] 35 75 [2] 29 5a }

  condition:
    any of them
}