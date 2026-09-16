rule TTP_XOR_QUAD_CurrentVersionRun_2846 {
  strings:
    $key_2846 = { 7b 29 [2] 5f 27 [2] 74 0b [2] 5a 29 [2] 4e 32 [2] 41 28 [2] 5f 35 [2] 5d 34 [2] 46 32 [2] 5a 35 [2] 46 1a }

  condition:
    any of them
}