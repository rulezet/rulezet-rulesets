rule TTP_XOR_QUAD_CurrentVersionRun_1004 {
  strings:
    $key_1004 = { 43 6b [2] 67 65 [2] 4c 49 [2] 62 6b [2] 76 70 [2] 79 6a [2] 67 77 [2] 65 76 [2] 7e 70 [2] 62 77 [2] 7e 58 }

  condition:
    any of them
}