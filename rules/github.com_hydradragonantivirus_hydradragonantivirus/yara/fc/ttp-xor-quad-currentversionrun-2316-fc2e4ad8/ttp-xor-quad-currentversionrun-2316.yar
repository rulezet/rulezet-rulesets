rule TTP_XOR_QUAD_CurrentVersionRun_2316 {
  strings:
    $key_2316 = { 70 79 [2] 54 77 [2] 7f 5b [2] 51 79 [2] 45 62 [2] 4a 78 [2] 54 65 [2] 56 64 [2] 4d 62 [2] 51 65 [2] 4d 4a }

  condition:
    any of them
}