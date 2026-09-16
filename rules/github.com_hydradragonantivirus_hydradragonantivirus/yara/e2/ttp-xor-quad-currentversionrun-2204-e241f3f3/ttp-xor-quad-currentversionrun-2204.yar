rule TTP_XOR_QUAD_CurrentVersionRun_2204 {
  strings:
    $key_2204 = { 71 6b [2] 55 65 [2] 7e 49 [2] 50 6b [2] 44 70 [2] 4b 6a [2] 55 77 [2] 57 76 [2] 4c 70 [2] 50 77 [2] 4c 58 }

  condition:
    any of them
}